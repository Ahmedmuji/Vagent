import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import fitz


class AdminGuideMetadataExtractor:
    def __init__(self, pdf_path: str):
        self.pdf_path = os.path.abspath(pdf_path)
        self.doc = fitz.open(self.pdf_path)
        self.pdf_file_uri = Path(self.pdf_path).resolve().as_uri()

    def close(self) -> None:
        if self.doc is not None:
            self.doc.close()

    def extract(self) -> Dict[str, Any]:
        named_destinations = self.extract_named_destinations()
        bookmarks = self.extract_bookmarks(named_destinations)
        links = self.extract_internal_links()
        return {
            "pdf_path": self.pdf_path,
            "pdf_file_uri": self.pdf_file_uri,
            "page_count": self.doc.page_count,
            "bookmarks": bookmarks,
            "toc": bookmarks,
            "internal_links": links,
            "named_destinations": named_destinations,
            "flat_index": self.build_flat_index(bookmarks),
        }

    def extract_bookmarks(self, named_destinations: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        raw_toc = self.doc.get_toc(simple=False)
        entries: List[Dict[str, Any]] = []
        stack: List[Dict[str, Any]] = []
        named_by_page = self._named_destinations_by_page(named_destinations or [])
        for idx, item in enumerate(raw_toc):
            level = int(item[0])
            title = str(item[1]).strip()
            dest = item[3] if len(item) > 3 and isinstance(item[3], dict) else {}
            page = self._resolve_toc_page(item, dest)
            anchor = self._page_anchor(page)
            named_destination = self._extract_named_destination(dest) or named_by_page.get(page, "")
            while stack and int(stack[-1]["bookmark_level"]) >= level:
                stack.pop()
            parents = [entry["title"] for entry in stack]
            page_end = self._infer_page_end(raw_toc, idx, level, page)
            entry = {
                "id": f"toc_{idx}",
                "title": title,
                "page": page,
                "page_start": page,
                "page_end": page_end,
                "pdf_page": page,
                "printed_page": page,
                "bookmark_level": level,
                "level": level,
                "section_path": " > ".join(parents + [title]),
                "breadcrumb_path": " > ".join(parents + [title]),
                "contextual_title": " > ".join(parents + [title]),
                "parent_sections": parents,
                "anchor": anchor,
                "pdf_anchor": anchor,
                "pdf_uri": self._pdf_uri(page),
                "named_destination": named_destination,
                "destination": self._normalize_destination(dest),
            }
            entries.append(entry)
            stack.append(entry)
        return entries

    def extract_internal_links(self) -> List[Dict[str, Any]]:
        links: List[Dict[str, Any]] = []
        for page_index in range(self.doc.page_count):
            page = self.doc[page_index]
            for link_idx, link in enumerate(page.get_links()):
                kind = link.get("kind")
                target_page = link.get("page")
                uri = link.get("uri")
                if target_page is not None and target_page >= 0:
                    page_number = int(target_page) + 1
                    anchor = self._page_anchor(page_number)
                    links.append({
                        "id": f"link_{page_index + 1}_{link_idx}",
                        "source_page": page_index + 1,
                        "target_page": page_number,
                        "kind": int(kind) if kind is not None else None,
                        "anchor": anchor,
                        "pdf_anchor": anchor,
                        "pdf_uri": self._pdf_uri(page_number),
                        "destination": self._normalize_destination(link),
                        "rect": self._rect_to_list(link.get("from")),
                    })
                elif uri:
                    links.append({
                        "id": f"link_{page_index + 1}_{link_idx}",
                        "source_page": page_index + 1,
                        "target_page": None,
                        "kind": int(kind) if kind is not None else None,
                        "uri": uri,
                        "rect": self._rect_to_list(link.get("from")),
                    })
        return links

    def extract_named_destinations(self) -> List[Dict[str, Any]]:
        destinations: List[Dict[str, Any]] = []
        resolver = getattr(self.doc, "resolve_names", None)
        if resolver is None:
            return destinations
        try:
            names = resolver()
        except Exception:
            return destinations
        if not isinstance(names, dict):
            return destinations
        for name, dest in sorted(names.items()):
            page = None
            if isinstance(dest, dict):
                raw_page = dest.get("page")
                if isinstance(raw_page, int) and raw_page >= 0:
                    page = raw_page + 1
            anchor = self._page_anchor(page)
            destinations.append({
                "name": str(name),
                "named_destination": str(name),
                "page": page,
                "anchor": anchor,
                "pdf_anchor": anchor,
                "pdf_uri": self._pdf_uri(page),
                "destination": self._normalize_destination(dest if isinstance(dest, dict) else {}),
            })
        return destinations

    def build_flat_index(self, bookmarks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        flat: List[Dict[str, Any]] = []
        for entry in bookmarks:
            indexed = dict(entry)
            indexed["embedding_text"] = " | ".join([
                indexed.get("section_path", ""),
                indexed.get("title", ""),
                f"page {indexed.get('page', '')}",
            ])
            indexed["keywords"] = self._keywords(indexed.get("section_path", ""))
            indexed["domains"] = self._domains(indexed.get("section_path", ""))
            flat.append(indexed)
        return flat

    def save(self, output_path: str) -> str:
        metadata = self.extract()
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2, ensure_ascii=False)
        return output_path

    @staticmethod
    def _infer_page_end(raw_toc: List[List[Any]], index: int, level: int, page_start: int) -> int:
        page_end = page_start
        for next_item in raw_toc[index + 1:]:
            next_level = int(next_item[0])
            next_page = int(next_item[2]) if next_item[2] else page_start
            if next_level <= level:
                return max(page_start, next_page - 1)
            page_end = max(page_end, next_page)
        return page_end

    def _resolve_toc_page(self, item: List[Any], dest: Dict[str, Any]) -> int:
        raw_dest_page = dest.get("page")
        if isinstance(raw_dest_page, int) and raw_dest_page >= 0:
            return min(raw_dest_page + 1, self.doc.page_count)
        raw_item_page = item[2] if len(item) > 2 else None
        if isinstance(raw_item_page, int) and raw_item_page > 0:
            return min(raw_item_page, self.doc.page_count)
        return 1

    def _pdf_uri(self, page: Optional[int]) -> str:
        if not page:
            return ""
        return f"{self.pdf_file_uri}{self._page_anchor(page)}"

    @staticmethod
    def _page_anchor(page: Optional[int]) -> str:
        if not page:
            return ""
        return f"#page={page}"

    @staticmethod
    def _extract_named_destination(dest: Dict[str, Any]) -> str:
        for key in ("nameddest", "named_destination", "name", "dest", "destination"):
            value = dest.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    @staticmethod
    def _named_destinations_by_page(destinations: List[Dict[str, Any]]) -> Dict[int, str]:
        by_page: Dict[int, str] = {}
        for destination in destinations:
            page = destination.get("page")
            name = destination.get("named_destination") or destination.get("name")
            if isinstance(page, int) and isinstance(name, str) and name:
                by_page.setdefault(page, name)
        return by_page

    @staticmethod
    def _normalize_destination(dest: Dict[str, Any]) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {}
        for key, value in dest.items():
            if key == "to":
                normalized[key] = AdminGuideMetadataExtractor._point_to_list(value)
            elif isinstance(value, (str, int, float, bool)) or value is None:
                normalized[key] = value
        return normalized

    @staticmethod
    def _rect_to_list(rect: Optional[Any]) -> List[float]:
        if rect is None:
            return []
        return [float(rect.x0), float(rect.y0), float(rect.x1), float(rect.y1)]

    @staticmethod
    def _point_to_list(point: Optional[Any]) -> List[float]:
        if point is None:
            return []
        return [float(point.x), float(point.y)]

    @staticmethod
    def _keywords(text: str) -> List[str]:
        import re
        return sorted(set(re.findall(r"[a-z0-9]+(?:[-'][a-z0-9]+)*", text.lower())))

    @staticmethod
    def _domains(text: str) -> List[str]:
        import re
        lowered = text.lower()
        normalized = f" {lowered} "
        tokens = set(re.findall(r"[a-z0-9]+(?:[-'][a-z0-9]+)*", lowered))
        domains = []
        mappings = {
            "VPN": ("vpn", "ipsec", "ssl vpn", "remote access"),
            "Firewall Policy": ("firewall", "policy", "nat", "security policy"),
            "High Availability": ("ha", "high availability", "cluster"),
            "Routing": ("routing", "ospf", "bgp", "static route"),
            "Authentication": ("authentication", "ldap", "radius", "saml", "user"),
            "Logging": ("log", "logging", "fortianalyzer", "syslog"),
            "SD-WAN": ("sd-wan", "sdwan"),
            "Security Profiles": ("ips", "antivirus", "web filter", "application control"),
        }
        for domain, keywords in mappings.items():
            matched = False
            for keyword in keywords:
                if " " in keyword or "-" in keyword:
                    matched = keyword in normalized
                else:
                    matched = keyword in tokens
                if matched:
                    break
            if matched:
                domains.append(domain)
        return domains or ["General"]


def build_admin_guide_metadata_index(pdf_path: str, output_path: str) -> List[Dict[str, Any]]:
    extractor = AdminGuideMetadataExtractor(pdf_path)
    try:
        metadata = extractor.extract()
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(metadata["flat_index"], fh, indent=2, ensure_ascii=False)
        return metadata["flat_index"]
    finally:
        extractor.close()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Extract Fortinet Admin Guide PDF metadata for RAG enrichment.")
    parser.add_argument("--pdf", required=True, help="Path to the FortiOS Administration Guide PDF")
    parser.add_argument("--metadata-out", default=os.path.join("output", "admin_guide_pdf_metadata.json"))
    parser.add_argument("--index-out", default=os.path.join("output", "toc_flat_index.json"))
    args = parser.parse_args()
    extractor = AdminGuideMetadataExtractor(args.pdf)
    try:
        metadata = extractor.extract()
        os.makedirs(os.path.dirname(args.metadata_out) or ".", exist_ok=True)
        with open(args.metadata_out, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2, ensure_ascii=False)
        os.makedirs(os.path.dirname(args.index_out) or ".", exist_ok=True)
        with open(args.index_out, "w", encoding="utf-8") as fh:
            json.dump(metadata["flat_index"], fh, indent=2, ensure_ascii=False)
    finally:
        extractor.close()
    print(f"SUCCESS: metadata saved to {args.metadata_out}")
    print(f"SUCCESS: flat index saved to {args.index_out} ({len(metadata['flat_index'])} entries)")


if __name__ == "__main__":
    main()
