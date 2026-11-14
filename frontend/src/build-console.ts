import { readFileSync, writeFileSync } from "node:fs";
import { navigation, overview } from "./console-layout";

const path = "index.html";
const source = readFileSync(path, "utf8");
const replaceRegion = (html: string, region: string, markup: string) => {
  const start = `<!-- ${region}:start -->`;
  const end = `<!-- ${region}:end -->`;
  const from = html.indexOf(start);
  const to = html.indexOf(end);
  if (from < 0 || to < from) throw new Error(`Missing console region ${region}`);
  return html.slice(0, from + start.length) + markup + html.slice(to);
};
writeFileSync(path, replaceRegion(replaceRegion(source, "console-nav", navigation), "console-overview", overview));
