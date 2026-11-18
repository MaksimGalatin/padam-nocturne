# Вкладка «Семья» (18.11.2026): первая и стартовая; Совет и Ленты перенесены из «Суверенного мозга»; меню из 7 групп; 4 языка.
from padam import studio, studio_help

SRC = open(studio.__file__, encoding="utf-8").read()


def test_семья_стартовая_и_в_списке_вкладок():
    assert "const TABS = ['overview', 'family'," in SRC
    assert ": 'family';" in SRC and "let _ffCh = 'office';" in SRC
    assert "family" in studio_help._TABS


def test_совет_и_ленты_только_в_семье():
    fam = SRC.index('<section id="panel-family"')
    brain = SRC.index('<section id="panel-brain"')
    assert fam < SRC.index('id="ark-council-btn"') < brain
    assert fam < SRC.index('id="ff-box"') < brain
    assert SRC.count('id="ark-council-btn"') == 1 and SRC.count('id="ff-box"') == 1


def test_тексты_на_4_языках():
    for lg in ("ru", "en", "es", "zh"):
        s = studio.STRINGS[lg]
        for k in ("nav_family", "fam_title", "fam_agents_title", "fam_roles_title", "role_lance", "role_aria", "role_pixel",
                  "role_arc7", "role_bear", "role_aifa", "grp_memory", "grp_guard", "grp_cloud", "grp_more", "fam_quiet"):
            assert s.get(k), (lg, k)


def test_меню_группы_покрывают_все_вкладки():
    import re
    tabs = re.search(r"const TABS = \[(.*?)\];", SRC).group(1)
    tabs = [x.strip(" '") for x in tabs.split(",")]
    groups = re.search(r"const NAV_GROUPS = \[(.*?)\n\];", SRC, re.S).group(1)
    in_groups = re.findall(r"'([a-z0-9]+)'", groups)
    assert set(tabs) == {x for x in in_groups if not x.startswith("grp_")}
