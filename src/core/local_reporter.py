import logging
import os
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse

from fpdf import FPDF

log = logging.getLogger(__name__)


class LocalReportGenerator:
    def __init__(self):
        log.info("LocalReportGenerator: Inicializando")

    def generate_report(self, data, prompt_template=None):
        log.info("LocalReportGenerator: Gerando relatorio local...")

        history = data.get("history") or []
        vulnerabilities = data.get("vulnerabilities") or {}
        technologies = data.get("technologies") or {}

        if not history and not vulnerabilities and not technologies:
            return "Nenhum dado disponivel para gerar relatorio."

        total_requests = len(history)
        hosts = []
        methods_counter = Counter()
        status_group_counter = Counter()

        for entry in history:
            method = entry.get("method", "N/A")
            methods_counter[method] += 1

            status_value = entry.get("status", "N/A")
            status_str = str(status_value)
            if status_str and status_str[0].isdigit():
                status_group_counter[f"{status_str[0]}xx"] += 1
            else:
                status_group_counter["N/A"] += 1

            url = entry.get("url", "")
            if url:
                host = urlparse(url).hostname
                if host:
                    hosts.append(host)

        unique_hosts = sorted(set(hosts))
        vuln_total, severity_counts = self._count_vulnerabilities(vulnerabilities)
        tech_total = self._count_technologies(technologies)

        lines = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append("RELATORIO TECNICO - PROXYHUNTER")
        lines.append(f"Gerado em: {timestamp}")
        lines.append("Modo: local")
        lines.append("")

        host_preview_line = None
        if unique_hosts:
            host_preview = ", ".join(unique_hosts[:10])
            if len(unique_hosts) > 10:
                host_preview = f"{host_preview}, ..."
            host_preview_line = f"- Hosts: {host_preview}"

        lines.extend(self._format_section("RESUMO", [
            f"- Requisicoes analisadas: {total_requests}",
            f"- Hosts unicos: {len(unique_hosts)}",
            f"- Vulnerabilidades: {vuln_total}",
            f"- Tecnologias detectadas: {tech_total}",
            host_preview_line,
            self._format_counter_line("- Metodos", methods_counter),
            self._format_counter_line(
                "- Status por faixa",
                status_group_counter,
                order=["1xx", "2xx", "3xx", "4xx", "5xx", "N/A"],
            ),
        ]))

        lines.extend(self._format_vulnerabilities_section(vulnerabilities, severity_counts))
        lines.extend(self._format_technologies_section(technologies))
        lines.extend(self._format_history_section(history))

        return "\n".join(lines)

    def save_as_pdf(self, report_content, report_dir="reports"):
        log.info(f"LocalReportGenerator: Salvando PDF no diretorio '{report_dir}'...")

        if not os.path.exists(report_dir):
            log.info(f"LocalReportGenerator: Criando diretorio '{report_dir}'")
            os.makedirs(report_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(report_dir, f"report_{timestamp}.pdf")
        log.info(f"LocalReportGenerator: Caminho do arquivo: {filepath}")

        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, report_content)
            pdf.output(filepath)
            log.info(f"LocalReportGenerator: PDF salvo com sucesso em {filepath}")
            return filepath
        except Exception as e:
            log.error(f"LocalReportGenerator: Erro ao salvar PDF: {e}", exc_info=True)
            return None

    def _format_section(self, title, lines, trailing_blank=True):
        section = [title, "-" * len(title)]
        section.extend([line for line in lines if line])
        if trailing_blank:
            section.append("")
        return section

    def _format_counter_line(self, label, counter, order=None):
        if not counter:
            return None
        if order:
            items = [(key, counter[key]) for key in order if counter.get(key)]
        else:
            items = counter.most_common()
        formatted = ", ".join([f"{key}: {count}" for key, count in items])
        return f"{label}: {formatted}"

    def _count_vulnerabilities(self, vulnerabilities):
        total = 0
        severity_counts = Counter()
        for details in vulnerabilities.values():
            if isinstance(details, list):
                total += len(details)
                for detail in details:
                    severity = detail.get("severity", "Unknown")
                    severity_counts[severity] += 1
            else:
                total += 1
                severity_counts["Unknown"] += 1
        return total, severity_counts

    def _count_technologies(self, technologies):
        total = 0
        for techs in technologies.values():
            if isinstance(techs, list):
                total += len(techs)
        return total

    def _format_vulnerabilities_section(self, vulnerabilities, severity_counts):
        lines = self._format_section("VULNERABILIDADES", [], trailing_blank=False)

        if not vulnerabilities:
            lines.insert(2, "Nenhuma vulnerabilidade reportada.")
            lines.append("")
            return lines

        severity_line = self._format_counter_line(
            "- Por severidade",
            severity_counts,
            order=["Critical", "High", "Medium", "Low", "Info", "Unknown"],
        )
        if severity_line:
            lines.insert(2, severity_line)

        for vuln_type, details in vulnerabilities.items():
            if isinstance(details, list):
                lines.append(f"- {vuln_type} ({len(details)})")
                for detail in details:
                    lines.extend(self._format_vulnerability_detail(detail))
            else:
                lines.append(f"- {vuln_type}")

        lines.append("")
        return lines

    def _format_vulnerability_detail(self, detail):
        url = detail.get("url", "N/A")
        method = detail.get("method", "N/A")
        severity = detail.get("severity", "Unknown")
        source = detail.get("source", "N/A")
        description = detail.get("description", "")
        evidence = detail.get("evidence", "")

        lines = [f"  - {method} {url} | Severidade: {severity} | Origem: {source}"]

        if description:
            lines.append(f"    Descricao: {description}")

        if evidence and evidence != "N/A":
            preview = str(evidence)
            if len(preview) > 200:
                preview = f"{preview[:200]}..."
            lines.append(f"    Evidencia: {preview}")

        return lines

    def _format_technologies_section(self, technologies):
        lines = self._format_section("TECNOLOGIAS DETECTADAS", [], trailing_blank=False)

        if not technologies:
            lines.insert(2, "Nenhuma tecnologia detectada.")
            lines.append("")
            return lines

        for host, techs in technologies.items():
            if isinstance(techs, list) and techs:
                tech_list = ", ".join([
                    f"{tech.get('name', 'Unknown')} {tech.get('version', '')}".strip()
                    for tech in techs
                ])
            else:
                tech_list = "N/A"
            lines.append(f"- {host}: {tech_list}")

        lines.append("")
        return lines

    def _format_history_section(self, history):
        lines = self._format_section("HISTORICO DE REQUISICOES", [], trailing_blank=False)

        if not history:
            lines.insert(2, "Nenhuma requisicao encontrada.")
            lines.append("")
            return lines

        for entry in history:
            entry_id = entry.get("id", "N/A")
            method = entry.get("method", "N/A")
            url = entry.get("url", "N/A")
            status = entry.get("status", "N/A")
            lines.append(f"{entry_id} | {method} {url} | Status: {status}")

            vuln_entries = entry.get("vulnerabilities") or []
            vuln_types = []
            for vuln in vuln_entries:
                vuln_type = vuln.get("type", vuln.get("name", "Unknown"))
                vuln_types.append(vuln_type)
            if vuln_types:
                lines.append(f"  - Vulnerabilidades: {', '.join(vuln_types)}")

        lines.append("")
        return lines
