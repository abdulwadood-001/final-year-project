/** Route head() helper: page title + description (applied by useDocumentTitle in __root). */
export function pageHead(title: string, description: string) {
  return () => ({
    meta: [{ title: `${title} — HoneyBot-IoT` }, { name: "description", content: description }],
  });
}
