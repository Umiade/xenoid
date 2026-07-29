export default async function task(xenoid) {
  await xenoid.shell('getprop ro.product.model');
  await xenoid.launch('com.android.settings/.Settings');
  await xenoid.sleep(500);
  await xenoid.tap(540, 1800);
  await xenoid.swipe(540, 1600, 540, 400, 300);
  return { ok: true };
}
