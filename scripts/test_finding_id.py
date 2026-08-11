from pathlib import Path
import tempfile

from bugcontrol.config import Settings
from bugcontrol.db.store import Store, new_finding_id

td = tempfile.mkdtemp()
s = Settings(db_path=Path(td) / "t.db", artifact_dir=Path(td) / "a")
store = Store(s)
store._conn.execute(
    "INSERT INTO findings (id,kind,platform,program_handle,program_name,"
    "program_url,summary,details_json,created_at) "
    "VALUES ('f_8bbd7a','new_program','hackerone','prism','PRISM','u','s','{}','t')"
)
store._conn.commit()
assert store.get_finding("f_8bbd7a").id == "f_8bbd7a"
assert store.get_finding("f8bbd7a").id == "f_8bbd7a"
nid = new_finding_id()
assert "_" not in nid and nid.startswith("f")
print("ok", nid)
