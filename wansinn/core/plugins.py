import importlib.util,json
from .contracts import RouterAddon
class AddonLoadError(RuntimeError): pass
def load_addon(addon_id,addons_dir,app):
  d=addons_dir/addon_id; m=d/"manifest.json"; p=d/"plugin.py"
  if not m.exists() or not p.exists(): raise AddonLoadError(f"Add-on fehlt: {addon_id}")
  manifest=json.loads(m.read_text())
  spec=importlib.util.spec_from_file_location(f"wansinn_addons.{addon_id}",p)
  module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
  cls=getattr(module,manifest["entrypoint"]); addon=cls(app,manifest)
  if not isinstance(addon,RouterAddon): raise AddonLoadError("Entrypoint implementiert RouterAddon nicht")
  return addon
