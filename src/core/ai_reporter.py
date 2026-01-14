import google.generativeai as genai
from fpdf import FPDF
import os
from datetime import datetime
import logging

log = logging.getLogger(__name__)

class AIReportGenerator:
    def __init__(self, api_key, model_name='gemini-2.5-flash-lite'):
        self.api_key = api_key
        self.model_name = model_name
        log.info(f"AIReportGenerator: Inicializando com modelo {model_name}")
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(self.model_name)

    def generate_report(self, data, prompt_template):
        """
        Generates a report using the provided data and prompt template.
        """
        log.info("AIReportGenerator: Formatando prompt...")
        prompt = self._format_prompt(data, prompt_template)
        log.info(f"AIReportGenerator: Prompt formatado ({len(prompt)} caracteres)")
        
        try:
            log.info("AIReportGenerator: Enviando requisição para a API...")
            response = self.model.generate_content(prompt)
            log.info("AIReportGenerator: Resposta recebida da API")
            
            if response and response.text:
                log.info(f"AIReportGenerator: Relatório gerado com sucesso ({len(response.text)} caracteres)")
                return response.text
            else:
                log.warning("AIReportGenerator: API retornou resposta vazia")
                return None
                
        except Exception as e:
            log.error(f"AIReportGenerator: Erro ao gerar relatório: {e}", exc_info=True)
            return None

    def _format_prompt(self, data, prompt_template):
        """
        Formata os dados coletados em um texto estruturado para o prompt da IA.
        """
        log.debug(f"_format_prompt: Recebendo dados com {len(data.get('history', []))} entradas de histórico")
        log.debug(f"_format_prompt: Tipos de vulnerabilidades: {list(data.get('vulnerabilities', {}).keys())}")
        
        formatted_data = []

        try:
            # 1. Formatar Histórico de Requisições
            history = data.get("history", [])
            if history:
                formatted_data.append("--- Histórico de Requisições ---")
                for entry in history:
                    try:
                        req_line = f"ID: {entry.get('id', 'N/A')} | {entry.get('method', 'N/A')} {entry.get('url', 'N/A')} | Status: {entry.get('status', 'N/A')}"
                        formatted_data.append(req_line)

                        # Adiciona detalhes de vulnerabilidades, se existirem para esta entrada
                        if entry.get('vulnerabilities'):
                            formatted_data.append("  -> Vulnerabilidades Encontradas:")
                            for vuln in entry['vulnerabilities']:
                                try:
                                    log.debug(f"Processando vulnerabilidade: {vuln}")
                                    vuln_type = vuln.get('type', vuln.get('name', 'Unknown'))
                                    vuln_severity = vuln.get('severity', 'Unknown')
                                    formatted_data.append(f"     - {vuln_type} (Severidade: {vuln_severity})")
                                except Exception as e:
                                    log.error(f"Erro ao formatar vulnerabilidade {vuln}: {e}", exc_info=True)
                                    continue
                    except Exception as e:
                        log.warning(f"Erro ao formatar entrada do histórico: {e}")
                        continue
                formatted_data.append("\n")
        except Exception as e:
            log.error(f"Erro ao formatar histórico: {e}")


        try:
            # 2. Formatar Vulnerabilidades Gerais (que não estão no histórico)
            vulnerabilities = data.get("vulnerabilities", {})
            if vulnerabilities:
                formatted_data.append("--- Sumário de Vulnerabilidades ---")
                for vuln_name, details in vulnerabilities.items():
                    try:
                        formatted_data.append(f"- {vuln_name}:")
                        if isinstance(details, list):
                            for detail in details:
                                try:
                                    url = detail.get('url', 'N/A')
                                    evidence = detail.get('evidence', 'N/A')
                                    evidence_preview = evidence[:100] if evidence != 'N/A' else 'N/A'
                                    formatted_data.append(f"  - URL: {url} | Evidência: {evidence_preview}...")
                                except Exception as e:
                                    log.warning(f"Erro ao formatar detalhe de vulnerabilidade: {e}")
                                    continue
                    except Exception as e:
                        log.warning(f"Erro ao formatar tipo de vulnerabilidade {vuln_name}: {e}")
                        continue
                formatted_data.append("\n")
        except Exception as e:
            log.error(f"Erro ao formatar vulnerabilidades: {e}")

        try:
            # 3. Formatar Tecnologias Detectadas
            technologies = data.get("technologies", {})
            if technologies:
                formatted_data.append("--- Tecnologias Detectadas ---")
                for host, techs in technologies.items():
                    try:
                        if isinstance(techs, list):
                            tech_list = ", ".join([f"{tech.get('name', 'Unknown')} {tech.get('version', '')}".strip() for tech in techs])
                            formatted_data.append(f"- {host}: {tech_list}")
                    except Exception as e:
                        log.warning(f"Erro ao formatar tecnologias do host {host}: {e}")
                        continue
                formatted_data.append("\n")
        except Exception as e:
            log.error(f"Erro ao formatar tecnologias: {e}")

        if not formatted_data:
            formatted_data.append("Nenhum dado relevante foi encontrado para análise.")

        final_data_string = "\n".join(formatted_data)
        prompt = prompt_template.replace("{data}", final_data_string)
        return prompt

    def save_as_pdf(self, report_content, report_dir="reports"):
        """
        Saves the report content as a PDF file.
        """
        log.info(f"AIReportGenerator: Salvando PDF no diretório '{report_dir}'...")
        
        if not os.path.exists(report_dir):
            log.info(f"AIReportGenerator: Criando diretório '{report_dir}'")
            os.makedirs(report_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(report_dir, f"report_{timestamp}.pdf")
        log.info(f"AIReportGenerator: Caminho do arquivo: {filepath}")

        try:
            pdf = FPDF()
            pdf.add_page()
            # Usar uma fonte padrão (Arial) que suporta codificação latina.
            # Para suporte completo a UTF-8 de forma portável, seria necessário
            # embarcar um arquivo de fonte .ttf com a aplicação.
            # Esta abordagem evita que a aplicação quebre em sistemas não-Linux.
            pdf.set_font("Arial", size=12)

            # A biblioteca fpdf2 lida com a codificação utf-8 internamente
            # ao processar o texto.
            log.info("AIReportGenerator: Adicionando conteúdo ao PDF...")
            pdf.multi_cell(0, 10, report_content)

            # Salva o PDF
            log.info("AIReportGenerator: Salvando arquivo PDF...")
            pdf.output(filepath)
            log.info(f"AIReportGenerator: PDF salvo com sucesso em {filepath}")
            return filepath
            
        except Exception as e:
            log.error(f"AIReportGenerator: Erro ao salvar PDF: {e}", exc_info=True)
            return None

if __name__ == '__main__':
    # Example usage
    # This is for testing purposes and will be removed later.
    API_KEY = "YOUR_API_KEY" # Replace with a valid API key for testing
    if API_KEY == "YOUR_API_KEY":
        print("Please replace 'YOUR_API_KEY' with a valid API key to test the AI reporter.")
    else:
        reporter = AIReportGenerator(api_key=API_KEY)

        # Example data
        example_data = {
            "history": [
                {"id": 1, "method": "GET", "url": "http://example.com/login", "status": 200},
                {"id": 2, "method": "POST", "url": "http://example.com/login", "status": 401}
            ]
        }

        # Example prompt
        example_prompt = "Analyze the following HTTP traffic and provide a security assessment with actionable recommendations for a penetration tester:\n\n{data}"

        # Generate and save the report
        report = reporter.generate_report(example_data, example_prompt)
        if report:
            saved_path = reporter.save_as_pdf(report)
            print(f"Report saved to {saved_path}")
