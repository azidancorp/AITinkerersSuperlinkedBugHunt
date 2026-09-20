// Never invoked by the harness flows; present only so module resolution succeeds.
export default function $() {
  throw new Error("jquery stub: offline harness must not touch the DOM");
}
