// JSON Merge Patch (RFC 7386)
export function applyMergePatch<T extends object>(target: T, patch: Partial<T>): T {
  const result = { ...target };
  for (const key of Object.keys(patch) as (keyof T)[]) {
    const val = patch[key];
    if (val === null) {
      delete result[key];
    } else if (typeof val === "object" && !Array.isArray(val) && val !== null) {
      result[key] = applyMergePatch(
        (result[key] as object) ?? {},
        val as Partial<T[typeof key] & object>
      ) as T[typeof key];
    } else {
      result[key] = val as T[typeof key];
    }
  }
  return result;
}
