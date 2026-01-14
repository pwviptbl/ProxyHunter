import re
from mitmproxy import http

class TechnologyDetector:
    """
    Detects technologies used by a web application based on HTTP flows.
    """
    def __init__(self):
        # In a real-world scenario, this would be more sophisticated.
        # For now, we use simple regex and header checks.
        self.rules = {
            # Web Servers
            'Nginx': {'headers': {'Server': r'nginx'}},
            'Apache': {'headers': {'Server': r'Apache'}},
            'IIS': {'headers': {'Server': r'Microsoft-IIS'}},
            'LiteSpeed': {'headers': {'Server': r'LiteSpeed'}},

            # Backend Languages
            'PHP': {'headers': {'X-Powered-By': r'PHP', 'Set-Cookie': r'PHPSESSID'}},
            'ASP.NET': {'headers': {'X-Powered-By': r'ASP.NET', 'Set-Cookie': r'ASP.NET_SessionId'}},
            'Java': {'headers': {'Set-Cookie': r'JSESSIONID'}},

            # Frontend Libraries
            'jQuery': {'body': [r'jquery.js', r'jquery.min.js', r'jquery-\d\.\d+\.\d+' ]},
            'React': {'body': [r'react.js', r'react-dom.js', r'data-react-id', r'react-root']},
            'AngularJS': {'body': [r'angular.js', r'ng-app', r'ng-model']},
            'Vue.js': {'body': [r'vue.js', r'data-v-', r'id="app"']},

            # CMS
            'WordPress': {'body': [r'wp-content', r'wp-includes', r'wp-json']},
            'Joomla': {'body': [r'content="Joomla!', r'/media/com_']},
            'Drupal': {'headers': {'X-Generator': r'Drupal'}, 'body': [r'Drupal.settings']},
        }

    def detect(self, flow: http.HTTPFlow) -> set:
        """
        Analyzes an HTTP flow to detect technologies.

        Args:
            flow: The mitmproxy HTTPFlow object.

        Returns:
            A set of detected technology names (e.g., {'Nginx', 'PHP'}).
        """
        detected_technologies = set()

        if not flow.response or not flow.response.content:
            return detected_technologies

        response_headers = flow.response.headers
        response_body = flow.response.get_text(strict=False) or ""

        for tech, patterns in self.rules.items():
            # Check headers
            if 'headers' in patterns:
                for header, regex in patterns['headers'].items():
                    if header in response_headers and re.search(regex, response_headers[header], re.IGNORECASE):
                        detected_technologies.add(tech)

            # Check body
            if 'body' in patterns and response_body:
                for regex in patterns['body']:
                    if re.search(regex, response_body, re.IGNORECASE):
                        detected_technologies.add(tech)

        # Attempt to get version for some technologies
        # This is a simplified example
        if 'jQuery' in detected_technologies:
            match = re.search(r'jquery-([\d\.]+)\.js', response_body, re.IGNORECASE)
            if match:
                detected_technologies.remove('jQuery')
                detected_technologies.add(f'jQuery {match.group(1)}')

        return detected_technologies
