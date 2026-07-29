export default async function task(xenoid) {
  await xenoid.tap(540, 1800);
  await xenoid.sleep(300);
  return { ok: true, action: 'tap-home-area' };
}
