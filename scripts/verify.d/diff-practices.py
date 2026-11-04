#!/usr/bin/env python3
"""Check D345 documentation against the merge base.

Reuse doc-coverage's lexer so strings and comments cannot invent declarations.
Changed bodies count, not just changed signatures. Existing untouched items do
not need a retroactive cleanup. Like doc-coverage, this is a cheap structural
check, not a language parser: fields, variants and macro expansion need review.
"""
import argparse
import bisect
import difflib
import importlib.machinery
import importlib.util
from pathlib import Path
import re
import subprocess

SCRIPTS = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader('doc_coverage', str(SCRIPTS / 'doc-coverage'))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
dc = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(dc)


def git(*args):
    """Read repository state without a shell, preserving unusual path names."""
    return subprocess.check_output(['git', *args])


def language(path):
    """Choose supported source syntax, excluding generated and vendored files."""
    if any(part in dc.SKIP_DIRS for part in (p + '/' for p in Path(path).parts)) or path.endswith('.d.ts'):
        return None
    return {'.rs': 'rust', '.ts': 'ts', '.js': 'ts', '.mjs': 'ts', '.cjs': 'ts', '.swift': 'swift'}.get(Path(path).suffix)


def pairs(masked):
    """Pair delimiters in lexed source; offsets still refer to the real file."""
    stack, result = [], {}
    for i, ch in enumerate(masked):
        if ch in '([{':
            stack.append((ch, i))
        elif ch in ')]}' and stack and stack[-1][0] == {')': '(', ']': '[', '}': '{'}[ch]:
            _, start = stack.pop()
            result[start] = i
    return result


def item_end(masked, start, paired):
    """Find a declaration's body or terminator, skipping parameter delimiters."""
    i = start
    while i < len(masked):
        ch = masked[i]
        if ch == '{':
            return paired.get(i, len(masked) - 1) + 1
        if ch == ';':
            return i + 1
        if ch in '([' and i in paired:
            i = paired[i]
        i += 1
    return len(masked)


def items(src, lang):
    """Yield (head, end, name, documented) for explicit declarations.

    Trait implementations inherit their interface documentation. Function-local
    variables are not symbols; declarations nested in function bodies are left
    to review, matching the existing coverage tool's scope.
    """
    masked, comments, _ = dc.lex(src, lang)
    paired = pairs(masked)
    attr = {'rust': dc.RUST_ATTR, 'ts': dc.NO_ATTR, 'swift': dc.SWIFT_ATTR}[lang]
    doc = dc.Doc(masked, [c for c in comments if not re.search(r"@(module|file|fileoverview|packageDocumentation)\b", src[c[0]:c[1]])], attr)
    if lang == 'rust':
        # Scan after every statement or brace, just as doc-coverage does. Keep
        # each full body span so a changed return value also needs documentation.
        stack, last = [], -1
        for boundary in dc.RUST_BOUNDARY.finditer(masked):
            at = boundary.start()
            header = dc.RUST_ATTR_STRIP(masked[last + 1:at])
            match = dc.RUST_ITEM.match(header)
            parent = stack[-1] if stack else 'mod'
            kind = 'other'
            if match and parent in ('mod', 'impl', 'trait') and match['name'] != '_':
                head = at - len(header.lstrip())
                end = paired.get(at, at) + 1 if boundary[0] == '{' else at + 1
                documented = doc.item(head) or bool(re.search(r'#\[\s*doc\b', masked[last + 1:head]))
                if match['kw'] == 'mod' and boundary[0] == '{':
                    documented |= dc.inline_mod_doc(doc, masked, at)
                yield head, end, match['name'], documented
            if boundary[0] == '{':
                if match and match['kw'] in ('mod', 'trait'):
                    kind = match['kw']
                elif dc.RUST_BLOCK_IMPL.match(header):
                    kind = 'traitimpl' if dc.RUST_FOR.search(header) else 'impl'
                stack.append(kind)
            elif boundary[0] == '}' and stack:
                stack.pop()
            last = at
        return
    decl = dc.TS_DECL if lang == 'ts' else dc.SWIFT_DECL
    stack, pdepth, last = [], 0, 0
    for line in re.finditer(r'(?m)^.*$', masked):
        top = stack[-1] if stack else None
        match = None
        if pdepth == 0 and top in (None, 'type'):
            match = decl.match(line[0])
            if not match and lang == 'ts' and top == 'type':
                match = dc.TS_METHOD.match(line[0])
                if match and match['name'] in dc.TS_NOT_METHOD:
                    match = None
        if match:
            head = line.start() + len(line[0]) - len(line[0].lstrip())
            end = item_end(masked, line.start() + match.end(), paired)
            yield head, end, match['name'] or 'init', doc.item(head)
        for k, ch in enumerate(line[0]):
            at = line.start() + k
            if ch in '([':
                pdepth += 1
            elif ch in ')]':
                pdepth = max(0, pdepth - 1)
            elif ch == '{':
                type_header = dc.TS_CLASS_HEADER if lang == 'ts' else dc.SWIFT_TYPE_HEADER
                stack.append('type' if type_header.search(masked[last:at]) else 'other')
                last = at + 1
            elif ch == '}':
                if stack:
                    stack.pop()
                last = at + 1
            elif ch == ';':
                last = at + 1


def changed_lines(old, new):
    """Separate changed current lines from boundaries where old lines vanished."""
    changed, deleted = set(), set()
    old_lines = old.splitlines()
    for tag, left, right, a, b in difflib.SequenceMatcher(None, old_lines, new.splitlines(), autojunk=False).get_opcodes():
        if tag == 'delete':
            # Removing a surviving item's attributes changes that item, whereas
            # removing its predecessor must not implicate the following head.
            removed = '\n'.join(old_lines[left:right])
            if re.fullmatch(r'\s*(?:#!?\[[^\]]*\]\s*)+', removed):
                changed.add(a + 1)
            else:
                deleted.add(a + 1)
        elif tag != 'equal':
            changed.update(range(a + 1, b + 1))
    return changed, deleted


def without_shape_exceptions(src):
    """Ignore only retired lint metadata, never unrelated attributes or code."""
    def clean(match):
        """Preserve other lint names and reasons when a mixed attribute survives."""
        text = match[0]
        if not re.search(r'clippy::too_many_(?:lines|arguments)', text):
            return text
        text = re.sub(r'clippy::too_many_(?:lines|arguments)\s*,?\s*', '', text)
        text = re.sub(r',\s*(\)\])', r'\1', text)
        body = text[text.index('(') + 1:text.rindex(')')].strip().rstrip(',')
        return '' if not body or body.startswith('reason') else text
    return re.sub(r'(?m)^[ \t]*#!?\[allow\((?:[^\]]|\n)*?\)\][ \t]*(?://[^\n]*)?\n', clean, src)


def check_docs(path, old, src, lang):
    """Require docs on changed declarations and modules, ignoring lint-only edits."""
    # Removing the retired shape lints changes metadata, not item behaviour.
    if without_shape_exceptions(old) == without_shape_exceptions(src):
        return []
    masked, comments, _ = dc.lex(src, lang)
    # Compare normalized source, then map its surviving lines back to the file.
    normalized = without_shape_exceptions(src)
    normalized_changed, normalized_deleted = changed_lines(without_shape_exceptions(old), normalized)
    mapping = difflib.SequenceMatcher(None, src.splitlines(), normalized.splitlines(), autojunk=False)
    changed, deleted = set(), set()
    for tag, a, b, c, d in mapping.get_opcodes():
        if tag == 'equal':
            changed.update(a + 1 + n - (c + 1) for n in normalized_changed if c + 1 <= n <= d)
            deleted.update(a + 1 + n - (c + 1) for n in normalized_deleted if c + 1 <= n <= d)
    starts = [0] + [m.end() for m in re.finditer('\n', src)]
    line_of = lambda at: bisect.bisect_right(starts, at)
    findings = []
    for head, end, name, documented in items(src, lang):
        # A deletion at an item's first line belongs to the removed predecessor;
        # a boundary inside its surviving body still changes this item.
        touched = any(line_of(head) <= line <= line_of(end - 1) for line in changed)
        touched |= any(line_of(head) < line <= line_of(end - 1) for line in deleted)
        if not documented and touched:
            findings.append(f'{path}:{line_of(head)}: {name} needs a doc comment (D345)')
    if lang == 'rust':
        module_doc = bool(re.match(r'\s*(?:#!\[[^\]]*\]\s*)*$', masked[:comments[0][0]])) if comments else False
        module_doc = module_doc and comments[0][2] == 'inner'
    else:
        module_doc = dc.ts_module_documented(src, masked, comments, dc.TS_DECL if lang == 'ts' else dc.SWIFT_DECL)
    if not module_doc and (changed or deleted):
        findings.insert(0, f'{path}:1: changed module needs a doc comment (D345)')
    return findings


def main():
    """Compare the worktree (including staged edits) with the requested merge base."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('docs',))
    parser.add_argument('base', nargs='?', default='origin/dev')
    args = parser.parse_args()
    base = git('merge-base', 'HEAD', args.base).decode().strip()
    paths = set(git('diff', '--name-only', '--diff-filter=ACMR', '-z', base).decode().split('\0'))
    paths.update(git('ls-files', '--others', '--exclude-standard', '-z').decode().split('\0'))
    findings = []
    for path in sorted(filter(None, paths)):
        lang = language(path)
        if not lang:
            continue
        previous = subprocess.run(['git', 'show', f'{base}:{path}'], capture_output=True)
        old = previous.stdout.decode() if previous.returncode == 0 else ''
        src = Path(path).read_text()
        findings.extend(check_docs(path, old, src, lang))
    print('\n'.join(findings) if findings else f'diff {args.mode}: ok (merge base {base[:12]})')
    return bool(findings)


if __name__ == '__main__':
    raise SystemExit(main())
