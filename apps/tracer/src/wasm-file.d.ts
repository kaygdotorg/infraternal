/** Types a `.wasm` file imported with `{ type: "file" }`: the bundler copies it under a hashed name and the import is that name's URL. */
declare module "*.wasm" {
  const url: string;
  export default url;
}
