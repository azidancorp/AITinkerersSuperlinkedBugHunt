// Never invoked by the harness flows; present only so module resolution succeeds.
export const load = (_html) => {
  throw new Error("cheerio stub: offline harness must not parse HTML");
};
