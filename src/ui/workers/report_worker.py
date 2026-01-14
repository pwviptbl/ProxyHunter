from PySide6.QtCore import QThread, Signal
import logging

log = logging.getLogger(__name__)

class ReportWorker(QThread):
    """
    Worker thread to generate reports without blocking the UI.
    """
    report_finished = Signal(str)  # Emits the filepath of the saved report
    report_error = Signal(str)     # Emits an error message

    def __init__(self, report_generator, data: dict, prompt: str = ""):
        super().__init__()
        self.report_generator = report_generator
        self.data = data
        self.prompt = prompt

    def run(self):
        """
        Executes the report generation process.
        """
        try:
            log.info("ReportWorker: Iniciando execução...")
            
            # 1. Generate the report content
            log.info("ReportWorker: Chamando generate_report...")
            report_content = self.report_generator.generate_report(self.data, self.prompt)

            if not report_content:
                error_msg = "O gerador de relatorio nao retornou nenhum conteudo."
                log.error(f"ReportWorker: {error_msg}")
                self.report_error.emit(error_msg)
                return

            log.info(f"ReportWorker: Relatório gerado com sucesso ({len(report_content)} caracteres)")

            # 2. Save the content as a PDF
            log.info("ReportWorker: Salvando como PDF...")
            filepath = self.report_generator.save_as_pdf(report_content)

            if filepath:
                log.info(f"ReportWorker: PDF salvo em {filepath}")
                self.report_finished.emit(filepath)
            else:
                error_msg = "Falha ao salvar o relatório em PDF."
                log.error(f"ReportWorker: {error_msg}")
                self.report_error.emit(error_msg)

        except Exception as e:
            error_msg = f"Ocorreu um erro inesperado: {str(e)}"
            log.error(f"ReportWorker: {error_msg}", exc_info=True)
            self.report_error.emit(error_msg)
