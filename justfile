# Local development builds only — not used in CI/CD.

src_flag := if path_exists("../../proto") == "true" { "--src ../../proto" } else { "" }

default:
  tacplus build {{src_flag}}
