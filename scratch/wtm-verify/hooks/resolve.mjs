// Node customization hook that lets the REAL Who-Targets-Me ES modules load
// outside webpack, without touching the repo:
//  1. bare package imports that have no node_modules offline are redirected
//     to synthetic stubs under scratch/wtm-verify/stubs/
//  2. webpack-style extensionless / directory imports ("..", "./helpers",
//     "../utils/eu-countries") are resolved by trying "<spec>.js" then
//     "<spec>/index.js" — mirroring webpack resolution.
const stubs = {
  "@feathersjs/client": new URL("../stubs/feathers.mjs", import.meta.url).href,
  cheerio: new URL("../stubs/cheerio.mjs", import.meta.url).href,
  lodash: new URL("../stubs/lodash.mjs", import.meta.url).href,
  "jsonpath-plus": new URL("../stubs/jsonpath-plus.mjs", import.meta.url).href,
  jquery: new URL("../stubs/jquery.mjs", import.meta.url).href,
};

export async function resolve(specifier, context, nextResolve) {
  if (Object.prototype.hasOwnProperty.call(stubs, specifier)) {
    return { url: stubs[specifier], shortCircuit: true };
  }

  try {
    return await nextResolve(specifier, context);
  } catch (err) {
    const isRelative =
      specifier === "." ||
      specifier === ".." ||
      specifier.startsWith("./") ||
      specifier.startsWith("../");
    if (isRelative) {
      try {
        return await nextResolve(specifier + ".js", context);
      } catch {}
      try {
        return await nextResolve(specifier + "/index.js", context);
      } catch {}
    }
    throw err;
  }
}
