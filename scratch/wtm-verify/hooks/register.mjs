// Registers the resolution hook for every harness run:
//   node --import ./hooks/register.mjs <script.mjs>
import { register } from "node:module";

register(new URL("./resolve.mjs", import.meta.url));
