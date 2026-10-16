/** A map that forgets its oldest entries past `max` (insertion order; a set moves a key to the end). Browser-safe. */
export class BoundedMap<V> {
  private readonly m = new Map<string, V>();
  constructor(private readonly max: number) {}
  get(k: string): V | undefined {
    return this.m.get(k);
  }
  has(k: string): boolean {
    return this.m.has(k);
  }
  set(k: string, v: V): void {
    this.m.delete(k);
    this.m.set(k, v);
    while (this.m.size > this.max) this.m.delete(this.m.keys().next().value as string);
  }
  delete(k: string): void {
    this.m.delete(k);
  }
  get size(): number {
    return this.m.size;
  }
}
