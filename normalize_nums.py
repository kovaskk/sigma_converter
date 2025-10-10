from lxml import etree

def renumber_rule_ids(path_in: str, path_out: str | None = None, start_id: int = 1) -> int:
    parser = etree.XMLParser(remove_blank_text=False, remove_comments=False)
    tree = etree.parse(path_in, parser)
    root = tree.getroot()

    next_id = start_id
    changed = 0

    for rule in root.iterfind(".//rule"):
        rid = rule.get("id")
        if rid is None:
            continue
        new_id = next_id
        rule.set("id", str(new_id))
        changed += 1
        next_id += 1
        if rule.get("level") == "0":
            for ifsid in rule.findall("if_sid"):
                ifsid.text = str(new_id - 1)

    out = path_out or path_in
    tree.write(out, encoding="utf-8", xml_declaration=True, pretty_print=False)
    return changed

id_start = int(input("Введите стартовый id правила: "))
renumber_rule_ids("sigma.xml", "sigma.xml", start_id=id_start)