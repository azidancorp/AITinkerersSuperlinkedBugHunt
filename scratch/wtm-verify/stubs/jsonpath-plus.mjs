// Never invoked by the harness flows; present only so module resolution succeeds.
export const JSONPath = () => {
  throw new Error("jsonpath-plus stub: offline harness must not evaluate paths");
};
