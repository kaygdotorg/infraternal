/** Wraps a PNG in an `.ico` container so `/favicon.ico` is a real icon file (#518). */

/**
 * Returns the bytes of an `.ico` file holding the single PNG `png` (a square image of at most 256 pixels, such as
 * `icons/dark-32.png`). Browsers and bookmark tools that ask for `/favicon.ico` by habit read it directly. The PNG is
 * embedded as is, which every current browser accepts, so no image library is needed and the output is the same on
 * every build.
 */
export function pngToIco(png: Uint8Array): Uint8Array {
  const signature = [0x89, 0x50, 0x4e, 0x47];
  if (png.length < 24 || signature.some((byte, index) => png[index] !== byte)) {
    throw new Error("pngToIco: input is not a PNG");
  }
  const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  if (width === 0 || height === 0 || width > 256 || height > 256) {
    throw new Error(`pngToIco: ${width}x${height} does not fit an icon (1..256)`);
  }
  const out = new Uint8Array(22 + png.length);
  const head = new DataView(out.buffer);
  head.setUint16(2, 1, true); // type: icon
  head.setUint16(4, 1, true); // one image
  out[6] = width === 256 ? 0 : width; // 0 means 256 in this field
  out[7] = height === 256 ? 0 : height;
  head.setUint16(10, 1, true); // colour planes
  head.setUint16(12, 32, true); // bits per pixel
  head.setUint32(14, png.length, true); // image size
  head.setUint32(18, 22, true); // image offset: right after the 6 + 16 byte headers
  out.set(png, 22);
  return out;
}
