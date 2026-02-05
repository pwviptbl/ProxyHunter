"""
Prompts - Templates de prompts para o LLM do agente.

Este módulo contém os prompts usados pelo DecisionAgent
para comunicação com o LLM.
"""

SYSTEM_PROMPT = """Você é um agente de exploração web que mapeia rotas e funcionalidades de sites.
Seu objetivo é DESCOBRIR o máximo de páginas e endpoints possível, NÃO fazer login com sucesso.

FILOSOFIA: EXPLORAR E SEGUIR EM FRENTE
- Visite cada página UMA vez
- Preencha formulários com dados fictícios e submeta (para registrar requisições)
- Se algo falhar, NÃO insista - vá para outra página/funcionalidade
- Priorize descobrir NOVAS rotas sobre tentar fazer algo funcionar

AÇÕES DISPONÍVEIS:
- click: Clica em elemento (requer selector)
- type: Digita texto em campo (requer selector + value)
- navigate: Navega para URL (requer value = URL completa com http://)
- scroll: Rola página (value = up/down)
- wait: Aguarda (value = segundos, máx 3)
- done: Exploração concluída
- failed: Impossível continuar

RESPONDA SEMPRE EM JSON:
{
    "reasoning": "breve explicação",
    "action": "tipo da ação",
    "selector": "seletor CSS (se aplicável)",
    "value": "valor (se aplicável)"
}

REGRAS CRÍTICAS:
1. NUNCA tente a mesma ação mais de UMA vez
2. Se uma ação FALHOU ou timeout, IGNORE e vá para OUTRO elemento
3. Formulários: preencha campos, submeta, pronto - não espere sucesso
4. Após submeter formulário, volte à página inicial e explore outra área
5. Priorize botões: Login, Cadastre-se, Register, Sign up, etc.
6. Use URLs COMPLETAS (http://...) para navigate
7. Se explorou login E cadastro E outras áreas, use "done"
8. Máximo 2-3 segundos de wait, nunca mais
"""


def build_decision_prompt(
    objective: str,
    current_url: str,
    page_title: str,
    elements: list,
    action_history: list,
    context: str = "",
    max_history: int = 10,
) -> str:
    """
    Constrói prompt de decisão para o LLM.
    """
    # Formata elementos
    elements_text = _format_elements(elements[:30])
    
    # Formata histórico
    history_text = _format_history(action_history[-max_history:])
    
    # Conta falhas para dar contexto
    recent_failures = sum(1 for r in action_history[-5:] 
                         if hasattr(r, 'success') and not r.success)
    
    prompt = f"""OBJETIVO: {objective}

URL ATUAL: {current_url}
TÍTULO: {page_title}

ELEMENTOS DISPONÍVEIS (apenas os visíveis):
{elements_text}

HISTÓRICO RECENTE:
{history_text}
"""
    
    if recent_failures >= 2:
        prompt += f"\n⚠️ ATENÇÃO: {recent_failures} falhas recentes. Mude de estratégia - tente elemento/página diferente!\n"
    
    if context:
        prompt += f"\nCONTEXTO:\n{context}\n"
    
    prompt += "\nQual a próxima ação? (lembre: explorar e seguir em frente, não insistir)"
    
    return prompt


def _format_elements(elements: list) -> str:
    """Formata lista de elementos para o prompt."""
    if not elements:
        return "(nenhum elemento interativo)"
    
    lines = []
    for el in elements:
        line = f"- [{el.element_type}] selector=\"{el.selector}\""
        if el.text:
            line += f" text=\"{el.text[:40]}\""
        if el.placeholder:
            line += f" placeholder=\"{el.placeholder}\""
        lines.append(line)
    
    return "\n".join(lines)


def _format_history(history: list) -> str:
    """Formata histórico de ações para o prompt, incluindo erros."""
    if not history:
        return "(primeira ação)"
    
    lines = []
    for result in history[-8:]:  # Últimas 8
        action = result.action if hasattr(result, 'action') else result.get('action', {})
        
        if hasattr(action, 'action_type'):
            action_type = action.action_type.name if hasattr(action.action_type, 'name') else str(action.action_type)
            selector = action.selector or ""
            value = action.value or ""
        else:
            action_type = action.get('action_type', 'UNKNOWN')
            selector = action.get('selector', '')
            value = action.get('value', '')
        
        success = result.success if hasattr(result, 'success') else result.get('success', False)
        error = result.error if hasattr(result, 'error') else result.get('error', '')
        
        if success:
            status = "✓"
        else:
            status = "✗ FALHOU"
        
        line = f"  {status}: {action_type}"
        if selector:
            line += f" -> {selector[:40]}"
        if value:
            line += f" = {value[:20]}"
        
        # Erro resumido
        if not success and error:
            if "Timeout" in str(error):
                line += " [elemento não encontrado]"
            elif "invalid URL" in str(error).lower():
                line += " [URL inválida - use URL completa]"
            else:
                line += f" [erro]"
        
        lines.append(line)
    
    return "\n".join(lines)


def build_login_context(username: str, password: str) -> str:
    """
    Constrói contexto para páginas de login.
    """
    return f"""CREDENCIAIS PARA TESTE:
- Usuário: {username}
- Senha: {password}

Use esses dados para preencher o formulário. Submeta UMA vez e siga em frente.
"""
