const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const RESOURCE_TYPES = new Set(['memo', 'instructor-announcement']);

/**
 * Return a stable, type-qualified identifier without changing the database UUID.
 * Existing endpoints and previously stored UUIDs remain valid.
 */
export function formatResourceId(resourceType, id) {
  if (!RESOURCE_TYPES.has(resourceType) || typeof id !== 'string' || !UUID.test(id)) {
    throw new TypeError('INVALID_RESOURCE_ID');
  }
  return `${resourceType}:${id.toLowerCase()}`;
}

/**
 * Accept the old bare UUID or the new type-qualified ID.
 * A qualified ID for a different resource type is rejected.
 * Some routers decode "%3A" before passing the path parameter; accept either form.
 */
export function parseResourceId(value, expectedType) {
  if (!RESOURCE_TYPES.has(expectedType) || typeof value !== 'string') return null;

  if (UUID.test(value)) return value.toLowerCase();

  const prefix = expectedType.toLowerCase();
  let candidate = null;
  if (value.toLowerCase().startsWith(`${prefix}:`)) {
    candidate = value.slice(prefix.length + 1);
  } else if (value.toLowerCase().startsWith(`${prefix}%3a`)) {
    candidate = value.slice(prefix.length + 3);
  }

  return candidate && UUID.test(candidate) ? candidate.toLowerCase() : null;
}
