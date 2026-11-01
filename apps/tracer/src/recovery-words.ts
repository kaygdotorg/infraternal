/** Displays and acknowledges rotated BIP-39 words with the shared copy/tick feedback [25,99,103]. */
import { copyFeedback, confirmAction, swapIcon, CLIPBOARD, DOWNLOAD } from "../../../packages/ui/src/copy-feedback";
import { springCheckbox } from "../../../packages/ui/src/tick";

export function recoveryWords(body: HTMLElement, words: string[], saved: boolean, onSaved: (saved: boolean) => void, markMotion: (instant: boolean) => void): void {
    body.innerHTML = `<ol class="auth-words" id="recovery-words"></ol>
      <div class="auth-actions"><button class="icon-action" id="copy-recovery" type="button" aria-label="Copy recovery key">${swapIcon(CLIPBOARD)}</button>
        <button class="icon-action" id="download-recovery" type="button" aria-label="Download recovery key">${swapIcon(DOWNLOAD)}</button></div>
      <p class="auth-recovery-message" id="recovery-message" role="status"></p>
      <label class="auth-check"><input id="recovery-saved" type="checkbox" /><span>I stored them somewhere safe</span></label>`;
    const list = body.querySelector<HTMLOListElement>("#recovery-words")!;
    words.forEach((word, i) => {
      const item = document.createElement("li");
      const number = document.createElement("span");
      number.className = "auth-word-number";
      number.textContent = String(i + 1);
      const value = document.createElement("span");
      value.textContent = word;
      item.append(number, value);
      list.append(item);
    });
    const serializedWords = words.join(" ");
    body.querySelector<HTMLButtonElement>("#copy-recovery")!.addEventListener("click", async (event) => {
      const button = event.currentTarget as HTMLButtonElement;
      markMotion(true); // the copy status can change pane height; only the icon feedback should animate
      const copied = await copyFeedback(button, serializedWords, event.detail === 0);
      // The tick on the button is the whole confirmation (TASTE: an action's confirmation lives on the control).
      // The line only reports a failure, and a success clears one left by an earlier failed attempt. The advice
      // to store the words safely is said once, in the step's own lede.
      body.querySelector<HTMLElement>("#recovery-message")!.textContent = copied
        ? ""
        : "Copy is unavailable here. Select and copy the words.";
      button.blur();
    });
    body.querySelector<HTMLButtonElement>("#download-recovery")!.addEventListener("click", (event) => {
      const button = event.currentTarget as HTMLButtonElement;
      confirmAction(button, "Downloaded", event.detail === 0);
      const contents = words.map((word, i) => `${i + 1}. ${word}`).join("\n") + "\n";
      const url = URL.createObjectURL(new Blob([contents], { type: "text/plain;charset=utf-8" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "infraternal-recovery-key.txt";
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
      button.blur();
    });
    const checkbox = body.querySelector<HTMLInputElement>("#recovery-saved")!;
    checkbox.checked = saved;
    springCheckbox(checkbox);
    checkbox.addEventListener("change", () => {
      markMotion(checkbox.matches(":focus-visible"));
      onSaved(checkbox.checked);
    });
  }
