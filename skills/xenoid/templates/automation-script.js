// Xenoid JS automation task template
// Available API: xenoid.tap, xenoid.swipe, xenoid.sleep, xenoid.launch, xenoid.install, xenoid.uninstall, xenoid.shell

export default async function task(xenoid) {
  await xenoid.launch('com.android.settings/.Settings');
  await xenoid.sleep(1000);
  await xenoid.tap(540, 1800);
  return { ok: true };
}
