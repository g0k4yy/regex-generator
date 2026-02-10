from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import (JMenuItem, JPanel, JTextArea, JButton, JScrollPane, 
                         BoxLayout, JLabel, JDialog, JComboBox, JSeparator, 
                         SwingUtilities, JCheckBox, JSpinner, SpinnerNumberModel,
                         JOptionPane, JTabbedPane, Box, BorderFactory)
from javax.swing.border import EmptyBorder, TitledBorder
from java.awt import (Toolkit, BorderLayout, Dimension, FlowLayout, Font, 
                      GridLayout, GridBagLayout, GridBagConstraints, Insets, Color)
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener
from java.util import ArrayList
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    # Hard upper bound for regex length (code-level safety)
    HARD_MAX_REGEX_LENGTH = 500
    DEFAULT_MAX_REGEX_LENGTH = 100
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Regex Generator")
        callbacks.registerContextMenuFactory(self)
        
        # Default settings
        self.max_regex_length = self.DEFAULT_MAX_REGEX_LENGTH
        self.advanced_mode = False
        
        print("Regex Generator loaded successfully")
    
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        
        selected_text = self.getSelectedText(invocation)
        if selected_text:
            menu_item = JMenuItem("Generate Regex for Selection")
            
            class RegexActionListener(ActionListener):
                def __init__(self, extension, inv, txt):
                    self.extension = extension
                    self.invocation = inv
                    self.selected_text = txt
                
                def actionPerformed(self, event):
                    self.extension.generateRegex(self.invocation, self.selected_text)
            
            listener = RegexActionListener(self, invocation, selected_text)
            menu_item.addActionListener(listener)
            menu_list.add(menu_item)
        
        return menu_list
    
    def getSelectedText(self, invocation):
        """Extract the selected text from the invocation context"""
        selection_bounds = invocation.getSelectionBounds()
        
        if selection_bounds is None or selection_bounds[0] == selection_bounds[1]:
            return None
        
        context = invocation.getInvocationContext()
        
        if context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            message = invocation.getSelectedMessages()[0].getRequest()
        elif context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            message = invocation.getSelectedMessages()[0].getRequest()
        elif context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            message = invocation.getSelectedMessages()[0].getResponse()
        elif context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            message = invocation.getSelectedMessages()[0].getResponse()
        else:
            return None
        
        start = selection_bounds[0]
        end = selection_bounds[1]
        
        selected_bytes = message[start:end]
        selected_text = self._helpers.bytesToString(selected_bytes)
        
        return selected_text
    
    def generateRegex(self, invocation, selected_text):
        """Generate regex patterns and show dialog"""
        
        # Get surrounding context
        context_before, context_after = self.getSurroundingContext(invocation)
        
        # Generate patterns (now includes default textbook patterns)
        exact_patterns = self.createExactPatterns(selected_text)
        pattern_variations = self.createPatternVariations(selected_text, context_before, context_after)
        
        # Show dialog on EDT
        def showDialog():
            self.showRegexDialog(selected_text, exact_patterns, pattern_variations, 
                                context_before, context_after)
        
        SwingUtilities.invokeLater(showDialog)
    
    def getSurroundingContext(self, invocation):
        """Get text before and after the selection for context"""
        selection_bounds = invocation.getSelectionBounds()
        context = invocation.getInvocationContext()
        
        if context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            message = invocation.getSelectedMessages()[0].getRequest()
        elif context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            message = invocation.getSelectedMessages()[0].getRequest()
        elif context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            message = invocation.getSelectedMessages()[0].getResponse()
        elif context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            message = invocation.getSelectedMessages()[0].getResponse()
        else:
            return "", ""
        
        start = selection_bounds[0]
        end = selection_bounds[1]
        
        # Get up to 50 characters before and after
        context_start = max(0, start - 50)
        context_end = min(len(message), end + 50)
        
        before_bytes = message[context_start:start]
        after_bytes = message[end:context_end]
        
        context_before = self._helpers.bytesToString(before_bytes)
        context_after = self._helpers.bytesToString(after_bytes)
        
        return context_before, context_after
    
    def createExactPatterns(self, text):
        """Create exact match patterns"""
        patterns = []
        
        escaped_text = re.escape(text)
        
        # Captured exact match
        patterns.append({
            'name': 'Exact Match (Captured)',
            'pattern': '(' + escaped_text + ')',
            'description': 'Captures this exact value'
        })
        
        # Anchored exact match
        patterns.append({
            'name': 'Exact Match (Anchored)',
            'pattern': '^(' + escaped_text + ')$',
            'description': 'Matches entire line with this exact value'
        })
        
        return patterns
    
    def createPatternVariations(self, text, context_before, context_after):
        """Create pattern variations with ReDoS safety and limits"""
        
        variations = []
        pattern_set = set()  # For deduplication
        
        # Get context patterns
        prefix_pattern = self.extractContextPattern(context_before, is_before=True)
        suffix_pattern = self.extractContextPattern(context_after, is_before=False)
        
        in_json_quoted = prefix_pattern and re.search(r'"[\w-]+"\s*:\s*"$', prefix_pattern.replace('\\', ''))
        in_json_unquoted = prefix_pattern and re.search(r'"[\w-]+"\s*:\s*$', prefix_pattern.replace('\\', ''))
        in_html_attr = prefix_pattern and re.search(r'[\w-]+\s*=\s*"$', prefix_pattern.replace('\\', ''))
        
        # --- RECOMMENDED PATTERNS (Context-aware) ---
        
        # Exact with context (if context exists)
        if prefix_pattern or suffix_pattern:
            escaped_text = re.escape(text)
            context_regex = ""
            if prefix_pattern:
                context_regex += prefix_pattern
            context_regex += "(" + escaped_text + ")"
            if suffix_pattern:
                context_regex += suffix_pattern
            
            context_regex = self.applySafetyLimits(context_regex)
            
            if context_regex not in pattern_set and len(context_regex) <= self.max_regex_length:
                pattern_set.add(context_regex)
                variations.append({
                    'category': 'recommended',
                    'name': '[RECOMMENDED] Exact with Context',
                    'pattern': context_regex,
                    'description': 'Recommended: Exact value with surrounding context'
                })
        
        # JSON field - any value (SAFE)
        if in_json_quoted:
            safe_pattern = prefix_pattern + r'([^"]{1,200})' + suffix_pattern
            safe_pattern = self.applySafetyLimits(safe_pattern)
            
            if safe_pattern not in pattern_set and len(safe_pattern) <= self.max_regex_length:
                pattern_set.add(safe_pattern)
                variations.append({
                    'category': 'recommended',
                    'name': '[RECOMMENDED] JSON Field - Any Value',
                    'pattern': safe_pattern,
                    'description': 'Recommended: Captures any value in this JSON field (safe)'
                })
        
        # HTML attribute - any value (SAFE)
        elif in_html_attr:
            safe_pattern = prefix_pattern + r'([^"\']{1,200})' + suffix_pattern
            safe_pattern = self.applySafetyLimits(safe_pattern)
            
            if safe_pattern not in pattern_set and len(safe_pattern) <= self.max_regex_length:
                pattern_set.add(safe_pattern)
                variations.append({
                    'category': 'recommended',
                    'name': '[RECOMMENDED] HTML Attribute - Any Value',
                    'pattern': safe_pattern,
                    'description': 'Recommended: Captures any value in this attribute (safe)'
                })
        
        # --- TYPE-BASED PATTERNS ---
        
        # URL patterns (with or without protocol)
        if re.match(r'^https?://', text):
            self._addUrlPatterns(variations, pattern_set, text)
        # NEW FEATURE: Domain patterns without protocol
        elif self._isDomainWithoutProtocol(text):
            self._addDomainPatterns(variations, pattern_set, text)
        
        # Email patterns
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', text):
            self._addEmailPatterns(variations, pattern_set, text)
        
        # ID/Token patterns
        if len(text) > 5 and re.search(r'[a-zA-Z0-9]', text):
            self._addIdTokenPatterns(variations, pattern_set, text)
        
        # Numeric patterns
        if re.match(r'^\d+$', text):
            self._addNumericPatterns(variations, pattern_set, text)
        
        # Separator-based patterns
        if '-' in text or '_' in text or '.' in text:
            self._addSeparatorPatterns(variations, pattern_set, text)
        
        # Add default textbook patterns to variations
        self._addDefaultTextbookPatterns(variations, pattern_set)
        
        # Limit to top patterns
        return self._limitAndSortPatterns(variations)
    
    def _addDefaultTextbookPatterns(self, variations, pattern_set):
        """Add default textbook patterns to variations list"""
        
        textbook = [
            {
                'name': '[DEFAULT] JWT Token',
                'pattern': r'(eyJ[a-zA-Z0-9_-]{10,100}\.[a-zA-Z0-9_-]{10,100}\.[a-zA-Z0-9_-]{10,100})',
                'description': 'JSON Web Token (header.payload.signature)'
            },
            {
                'name': '[DEFAULT] JSESSIONID',
                'pattern': r'(JSESSIONID=[A-F0-9]{16,64})',
                'description': 'Java JSESSIONID cookie'
            },
            {
                'name': '[DEFAULT] ASP.NET Session ID',
                'pattern': r'(ASP\.NET_SessionId=[a-zA-Z0-9]{16,64})',
                'description': 'ASP.NET session identifier'
            },
            {
                'name': '[DEFAULT] Generic Session/Token',
                'pattern': r'([a-zA-Z0-9_-]{20,80})',
                'description': 'Generic bounded session/token value'
            },
            {
                'name': '[DEFAULT] UUID',
                'pattern': r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
                'description': 'UUID (8-4-4-4-12 hex)'
            },
            {
                'name': '[DEFAULT] IPv4 Address',
                'pattern': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                'description': 'IPv4 address'
            },
            {
                'name': '[DEFAULT] Email',
                'pattern': r'([a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,100}\.[a-zA-Z]{2,10})',
                'description': 'Email address (bounded)'
            },
            {
                'name': '[DEFAULT] MD5 Hash',
                'pattern': r'([a-fA-F0-9]{32})',
                'description': 'MD5 hash (32 hex chars)'
            },
            {
                'name': '[DEFAULT] SHA1 Hash',
                'pattern': r'([a-fA-F0-9]{40})',
                'description': 'SHA1 hash (40 hex chars)'
            },
            {
                'name': '[DEFAULT] SHA256 Hash',
                'pattern': r'([a-fA-F0-9]{64})',
                'description': 'SHA256 hash (64 hex chars)'
            },
            {
                'name': '[DEFAULT] Base64',
                'pattern': r'([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)',
                'description': 'Base64 encoded string'
            },
            {
                'name': '[DEFAULT] MAC Address',
                'pattern': r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})',
                'description': 'MAC address'
            },
            {
                'name': '[DEFAULT] Hex Color',
                'pattern': r'(#[a-fA-F0-9]{6})',
                'description': 'Hex color code'
            },
            {
                'name': '[DEFAULT] Date (YYYY-MM-DD)',
                'pattern': r'(\d{4}-\d{2}-\d{2})',
                'description': 'ISO date format'
            },
            {
                'name': '[DEFAULT] Date (MM/DD/YYYY)',
                'pattern': r'(\d{2}/\d{2}/\d{4})',
                'description': 'US date format'
            },
            {
                'name': '[DEFAULT] Time (24h)',
                'pattern': r'(\d{2}:\d{2}:\d{2})',
                'description': '24-hour time (HH:MM:SS)'
            },
            {
                'name': '[DEFAULT] Phone (US)',
                'pattern': r'(\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})',
                'description': 'US phone number'
            },
            {
                'name': '[DEFAULT] Credit Card',
                'pattern': r'(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})',
                'description': 'Credit card number (16 digits)'
            },
            {
                'name': '[DEFAULT] US SSN',
                'pattern': r'(\d{3}-\d{2}-\d{4})',
                'description': 'US Social Security Number (XXX-XX-XXXX)'
            }
        ]
        
        for p in textbook:
            p['category'] = 'default'
            if p['pattern'] not in pattern_set and len(p['pattern']) <= self.max_regex_length:
                pattern_set.add(p['pattern'])
                variations.append(p)
    
    def _isDomainWithoutProtocol(self, text):
        """Check if text looks like a domain without protocol (e.g., www.youtube.com, youtube.com)"""
        # Should contain a dot and look like a domain
        # Should not start with protocol
        # Should not contain spaces or quotes
        if re.match(r'^https?://', text):
            return False
        
        # Basic domain pattern: word characters, dots, hyphens, but must have at least one dot
        # and should look like a valid domain structure
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(/.*)?$'
        return re.match(domain_pattern, text) is not None
    
    def _addDomainPatterns(self, variations, pattern_set, text):
        """Add domain-specific patterns for domains without protocol (NEW FEATURE)"""
        # Extract just the domain part (without path if present)
        domain_match = re.match(r'^([^/\s"]+)', text)
        if not domain_match:
            return
        
        domain = domain_match.group(1)
        
        patterns = []
        
        # Pattern 1: Exact domain match
        exact_domain_pattern = r'(' + re.escape(domain) + r')'
        if len(exact_domain_pattern) <= self.max_regex_length:
            patterns.append({
                'category': 'type',
                'name': '[TYPE] Domain - Exact Match',
                'pattern': exact_domain_pattern,
                'description': 'Matches exact domain: ' + domain
            })
        
        # Pattern 2: Domain with optional path
        domain_with_path = r'(' + re.escape(domain) + r'[^\s"]*)'
        if len(domain_with_path) <= self.max_regex_length:
            patterns.append({
                'category': 'type',
                'name': '[TYPE] Domain - With Path',
                'pattern': domain_with_path,
                'description': 'Matches domain with any path: ' + domain
            })
        
        # Pattern 3: Subdomain variations
        # Extract base domain (e.g., youtube.com from www.youtube.com)
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])  # Get last two parts (e.g., youtube.com)
            
            # Match any subdomain of the base domain
            subdomain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.' + re.escape(base_domain) + r')'
            if len(subdomain_pattern) <= self.max_regex_length:
                patterns.append({
                    'category': 'type',
                    'name': '[TYPE] Domain - Any Subdomain',
                    'pattern': subdomain_pattern,
                    'description': 'Matches any subdomain of ' + base_domain
                })
            
            # Top-level domain only (e.g., youtube.com)
            if domain != base_domain:  # Only if we actually have a subdomain
                tld_pattern = r'(' + re.escape(base_domain) + r')'
                if len(tld_pattern) <= self.max_regex_length:
                    patterns.append({
                        'category': 'type',
                        'name': '[TYPE] Domain - Base Only',
                        'pattern': tld_pattern,
                        'description': 'Matches base domain: ' + base_domain
                    })
        
        # Pattern 4: With optional protocol prefix
        with_protocol = r'((?:https?://)?' + re.escape(domain) + r'[^\s"]*)'
        if len(with_protocol) <= self.max_regex_length:
            patterns.append({
                'category': 'type',
                'name': '[TYPE] Domain - Optional Protocol',
                'pattern': with_protocol,
                'description': 'Matches domain with optional http:// or https:// prefix'
            })
        
        for p in patterns:
            if p['pattern'] not in pattern_set:
                pattern_set.add(p['pattern'])
                variations.append(p)
    
    def _addUrlPatterns(self, variations, pattern_set, text):
        """Add URL-specific patterns"""
        patterns = [
            {
                'category': 'type',
                'name': '[TYPE] URL - Any Protocol',
                'pattern': r'(https?://[^\s"]{1,200})',
                'description': 'Matches HTTP or HTTPS URLs (safe bounded)'
            }
        ]
        
        protocol = 'https' if text.startswith('https') else 'http'
        patterns.append({
            'category': 'type',
            'name': '[TYPE] URL - ' + protocol.upper() + ' Only',
            'pattern': '(' + protocol + r'://[^\s"]{1,200})',
            'description': 'Matches only ' + protocol.upper() + ' URLs'
        })
        
        # Domain extraction
        domain_match = re.search(r'https?://([^/\s"]+)', text)
        if domain_match:
            domain = domain_match.group(1)
            
            # Same domain pattern
            domain_pattern = r'(https?://' + re.escape(domain) + r'[^\s"]{0,150})'
            if len(domain_pattern) <= self.max_regex_length:
                patterns.append({
                    'category': 'type',
                    'name': '[TYPE] URL - Same Domain',
                    'pattern': domain_pattern,
                    'description': 'URLs from ' + domain[:30] + ('...' if len(domain) > 30 else '')
                })
            
            # NEW: Add subdomain pattern for URLs
            parts = domain.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
                subdomain_url_pattern = r'(https?://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.' + re.escape(base_domain) + r'[^\s"]{0,150})'
                if len(subdomain_url_pattern) <= self.max_regex_length:
                    patterns.append({
                        'category': 'type',
                        'name': '[TYPE] URL - Any Subdomain',
                        'pattern': subdomain_url_pattern,
                        'description': 'URLs from any subdomain of ' + base_domain
                    })
        
        for p in patterns:
            if p['pattern'] not in pattern_set:
                pattern_set.add(p['pattern'])
                variations.append(p)
    
    def _addEmailPatterns(self, variations, pattern_set, text):
        """Add email-specific patterns"""
        pattern = r'([a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,100}\.[a-zA-Z]{2,10})'
        
        if pattern not in pattern_set:
            pattern_set.add(pattern)
            variations.append({
                'category': 'type',
                'name': '[TYPE] Email - Any Address',
                'pattern': pattern,
                'description': 'Matches any email address (safe bounded)'
            })
    
    def _addIdTokenPatterns(self, variations, pattern_set, text):
        """Add ID/Token patterns"""
        text_len = len(text)
        
        # Flexible length ID
        min_len = max(5, text_len - 10)
        max_len = min(text_len + 10, 100)
        
        pattern = r'([a-zA-Z0-9_-]{' + str(min_len) + ',' + str(max_len) + '})'
        
        if pattern not in pattern_set:
            pattern_set.add(pattern)
            variations.append({
                'category': 'type',
                'name': '[TYPE] ID - Flexible Length',
                'pattern': pattern,
                'description': 'Alphanumeric ID, length ' + str(min_len) + '-' + str(max_len)
            })
    
    def _addNumericPatterns(self, variations, pattern_set, text):
        """Add numeric patterns"""
        exact_len = len(text)
        
        pattern = r'(\d{' + str(exact_len) + '})'
        
        if pattern not in pattern_set:
            pattern_set.add(pattern)
            variations.append({
                'category': 'type',
                'name': '[TYPE] Number - Exact Length',
                'pattern': pattern,
                'description': str(exact_len) + '-digit number'
            })
    
    def _addSeparatorPatterns(self, variations, pattern_set, text):
        """Add separator-based patterns (simplified)"""
        
        if '-' in text and len(text.split('-')) > 1:
            parts = text.split('-')
            if len(parts) <= 5:  # Limit complexity
                pattern_parts = []
                for part in parts:
                    part_len = len(part)
                    if part_len > 0:
                        if re.match(r'^\d+$', part):
                            pattern_parts.append(r'\d{' + str(part_len) + '}')
                        elif re.match(r'^[a-fA-F0-9]+$', part):
                            pattern_parts.append(r'[a-fA-F0-9]{' + str(part_len) + '}')
                        else:
                            pattern_parts.append(r'[a-zA-Z0-9]{' + str(part_len) + '}')
                
                if pattern_parts:
                    pattern = r'(' + r'-'.join(pattern_parts) + r')'
                    
                    if pattern not in pattern_set and len(pattern) <= self.max_regex_length:
                        pattern_set.add(pattern)
                        variations.append({
                            'category': 'type',
                            'name': '[TYPE] Dash-Separated Pattern',
                            'pattern': pattern,
                            'description': 'Matches dash-separated structure'
                        })
    
    def _limitAndSortPatterns(self, variations):
        """Sort patterns by category priority and limit to prevent UI issues"""
        
        # Sort by category priority
        priority = {'recommended': 0, 'type': 1, 'default': 2}
        sorted_variations = sorted(variations, key=lambda x: priority.get(x.get('category', 'default'), 3))
        
        # Limit total patterns to prevent dropdown performance issues
        # Keep top patterns from each category
        MAX_TOTAL_PATTERNS = 30  # Reasonable limit for dropdown
        
        if len(sorted_variations) > MAX_TOTAL_PATTERNS:
            # Keep more recommended and type patterns, fewer default
            recommended = [v for v in sorted_variations if v.get('category') == 'recommended']
            type_patterns = [v for v in sorted_variations if v.get('category') == 'type']
            default_patterns = [v for v in sorted_variations if v.get('category') == 'default']
            
            # Allocate space: recommended (all), type (up to 10), default (fill remaining)
            result = []
            result.extend(recommended)  # Keep all recommended
            result.extend(type_patterns[:10])  # Keep up to 10 type patterns
            
            remaining_space = MAX_TOTAL_PATTERNS - len(result)
            if remaining_space > 0:
                result.extend(default_patterns[:remaining_space])  # Fill with defaults
            
            return result
        
        return sorted_variations
    
    def applySafetyLimits(self, pattern):
        """Apply ReDoS safety rules to pattern"""
        
        # Hard length limit
        if len(pattern) > self.HARD_MAX_REGEX_LENGTH:
            return pattern[:self.HARD_MAX_REGEX_LENGTH]
        
        # Detect and block dangerous patterns
        dangerous = [r'\.\*\.\*', r'\(\.\+\)\+', r'\(\.\*\)\+', r'\{0,\}']
        
        for danger in dangerous:
            if re.search(danger, pattern):
                # Fallback to safe bounded pattern
                return r'(.{1,100})'
        
        # Replace unbounded quantifiers
        pattern = re.sub(r'\(\.\+\)', r'(.{1,100})', pattern)
        pattern = re.sub(r'\(\.\*\)', r'(.{0,100})', pattern)
        
        return pattern
    
    def extractContextPattern(self, context, is_before):
        """Extract context pattern with flexible anchors"""
        
        if not context:
            return ""
        
        if is_before:
            snippet = context[-50:] if len(context) > 50 else context
            
            # JSON key pattern (flexible)
            match = re.search(r'"([\w-]+)"\s*:\s*"?$', snippet)
            if match:
                key = match.group(1)
                return '"' + key + r'"\s*:\s*"'
            
            # HTML attribute (flexible)
            match = re.search(r'([\w-]+)\s*=\s*"$', snippet)
            if match:
                attr = match.group(1)
                return attr + r'\s*=\s*"'
            
            return ""
        
        else:  # is_after
            snippet = context[:30] if len(context) > 30 else context
            
            if snippet.startswith('"') or snippet.startswith("'"):
                return snippet[0]
            
            return ""
    
    def showRegexDialog(self, selected_text, exact_patterns, pattern_variations, 
                       context_before, context_after):
        """Show regex dialog with cross-platform compatible layout"""
        
        dialog = JDialog()
        dialog.setTitle("Regex Generator")
        dialog.setModal(True)
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE)

        # -- helpers --------------------------------------------------------------

        def make_section_label(text):
            lbl = JLabel(text)
            lbl.setFont(Font(lbl.getFont().getName(), Font.BOLD, 13))
            return lbl

        def make_bold_label(text):
            lbl = JLabel(text)
            lbl.setFont(Font(lbl.getFont().getName(), Font.BOLD, 12))
            return lbl

        def make_textarea(text, rows, editable=True):
            ta = JTextArea(text)
            ta.setEditable(editable)
            ta.setLineWrap(True)
            ta.setWrapStyleWord(True)
            ta.setRows(rows)
            ta.setFont(Font("Monospaced", Font.PLAIN, 12))
            return ta

        def make_scroll(ta):
            sp = JScrollPane(ta)
            sp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
            sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
            return sp

        def make_separator():
            sep = JSeparator()
            return sep

        def strut(px):
            return Box.createVerticalStrut(px)

        # -- main content panel (Y-axis BoxLayout, inside a scroll pane) ----------
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setBorder(EmptyBorder(12, 14, 12, 14))

        def add_full_width(panel, component):
            """Add a component and force it to fill the full width."""
            component.setAlignmentX(0.0)
            if hasattr(component, 'setMaximumSize'):
                component.setMaximumSize(Dimension(10000, component.getPreferredSize().height if component.getPreferredSize().height > 0 else 200))
            panel.add(component)

        def add_left_row(panel, *components):
            """Add a left-aligned row panel containing the given components."""
            row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
            row.setAlignmentX(0.0)
            for c in components:
                row.add(c)
            row.setMaximumSize(Dimension(10000, row.getPreferredSize().height + 4))
            panel.add(row)

        # -- Context preview ------------------------------------------------------
        if context_before or context_after:
            add_full_width(main_panel, make_bold_label("Context:"))
            main_panel.add(strut(4))

            preview_before = context_before[-30:] if len(context_before) > 30 else context_before
            preview_after  = context_after[:30]   if len(context_after)  > 30 else context_after
            context_preview = preview_before + "[" + selected_text + "]" + preview_after

            ctx_ta = make_textarea(context_preview, 2, editable=False)
            ctx_scroll = make_scroll(ctx_ta)
            ctx_scroll.setAlignmentX(0.0)
            ctx_scroll.setMaximumSize(Dimension(10000, 56))
            ctx_scroll.setPreferredSize(Dimension(640, 56))
            main_panel.add(ctx_scroll)
            main_panel.add(strut(8))

        # -- Selected text --------------------------------------------------------
        add_full_width(main_panel, make_bold_label("Selected Text:"))
        main_panel.add(strut(4))

        sel_ta = make_textarea(selected_text[:200], 1, editable=False)
        sel_scroll = make_scroll(sel_ta)
        sel_scroll.setAlignmentX(0.0)
        sel_scroll.setMaximumSize(Dimension(10000, 44))
        sel_scroll.setPreferredSize(Dimension(640, 44))
        main_panel.add(sel_scroll)

        main_panel.add(strut(10))
        add_full_width(main_panel, make_separator())
        main_panel.add(strut(10))

        # -- 1. Exact Match Section -----------------------------------------------
        add_full_width(main_panel, make_section_label("1. Exact Match Options:"))
        main_panel.add(strut(8))

        exact_items = [p['name'] for p in exact_patterns]
        exact_dropdown = JComboBox(exact_items)
        add_left_row(main_panel, JLabel("Select type:"), exact_dropdown)
        main_panel.add(strut(6))

        exact_desc = JLabel(exact_patterns[0]['description'])
        exact_desc.setAlignmentX(0.0)
        main_panel.add(exact_desc)
        main_panel.add(strut(4))

        exact_ta = make_textarea(exact_patterns[0]['pattern'], 2)
        exact_scroll = make_scroll(exact_ta)
        exact_scroll.setAlignmentX(0.0)
        exact_scroll.setMaximumSize(Dimension(10000, 58))
        exact_scroll.setPreferredSize(Dimension(640, 58))
        main_panel.add(exact_scroll)
        main_panel.add(strut(6))

        exact_copy_btn = JButton("Copy to Clipboard")
        exact_copy_btn.setAlignmentX(0.0)

        def copyExact(event):
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(exact_ta.getText()), None)
            exact_copy_btn.setText("Copied!")
            from javax.swing import Timer
            def reset(e):
                exact_copy_btn.setText("Copy to Clipboard")
            t = Timer(1500, reset)
            t.setRepeats(False)
            t.start()

        exact_copy_btn.addActionListener(copyExact)
        add_left_row(main_panel, exact_copy_btn)

        def onExactChange(event):
            idx = exact_dropdown.getSelectedIndex()
            if 0 <= idx < len(exact_patterns):
                p = exact_patterns[idx]
                exact_ta.setText(p['pattern'])
                exact_desc.setText(p['description'])

        exact_dropdown.addActionListener(onExactChange)

        main_panel.add(strut(10))
        add_full_width(main_panel, make_separator())
        main_panel.add(strut(10))

        # -- 2. Pattern Variations Section -----------------------------------------
        if pattern_variations:
            add_full_width(main_panel, make_section_label("2. Pattern Variations:"))
            main_panel.add(strut(8))

            dropdown_items = [var['name'] for var in pattern_variations]
            pvar_dropdown = JComboBox(dropdown_items)
            pvar_dropdown.setMaximumRowCount(15)
            add_left_row(main_panel, JLabel("Select pattern:"), pvar_dropdown)
            main_panel.add(strut(6))

            pvar_desc = JLabel(pattern_variations[0]['description'])
            pvar_desc.setAlignmentX(0.0)
            main_panel.add(pvar_desc)
            main_panel.add(strut(4))

            pvar_ta = make_textarea(pattern_variations[0]['pattern'], 2)
            pvar_scroll = make_scroll(pvar_ta)
            pvar_scroll.setAlignmentX(0.0)
            pvar_scroll.setMaximumSize(Dimension(10000, 58))
            pvar_scroll.setPreferredSize(Dimension(640, 58))
            main_panel.add(pvar_scroll)
            main_panel.add(strut(6))

            pvar_copy_btn = JButton("Copy to Clipboard")
            pvar_copy_btn.setAlignmentX(0.0)

            def copyPattern(event):
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(StringSelection(pvar_ta.getText()), None)
                pvar_copy_btn.setText("Copied!")
                from javax.swing import Timer
                def reset(e):
                    pvar_copy_btn.setText("Copy to Clipboard")
                t = Timer(1500, reset)
                t.setRepeats(False)
                t.start()

            pvar_copy_btn.addActionListener(copyPattern)
            add_left_row(main_panel, pvar_copy_btn)

            def onDropdownChange(event):
                idx = pvar_dropdown.getSelectedIndex()
                if 0 <= idx < len(pattern_variations):
                    var = pattern_variations[idx]
                    pvar_ta.setText(var['pattern'])
                    pvar_desc.setText(var['description'])

            pvar_dropdown.addActionListener(onDropdownChange)

        main_panel.add(strut(10))
        add_full_width(main_panel, make_separator())
        main_panel.add(strut(10))

        # -- Settings Section ------------------------------------------------------
        settings_panel = self.createSettingsPanel(dialog)
        settings_panel.setAlignmentX(0.0)
        main_panel.add(settings_panel)

        main_panel.add(strut(12))

        # -- Close button ----------------------------------------------------------
        close_button = JButton("Close")

        def closeDialog(event):
            dialog.dispose()

        close_button.addActionListener(closeDialog)
        add_left_row(main_panel, close_button)

        # -- Wrap everything in a scroll pane so it never clips --------------------
        outer_scroll = JScrollPane(main_panel)
        outer_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        outer_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        outer_scroll.setBorder(BorderFactory.createEmptyBorder())

        dialog.getContentPane().setLayout(BorderLayout())
        dialog.getContentPane().add(outer_scroll, BorderLayout.CENTER)

        dialog.setMinimumSize(Dimension(660, 400))
        dialog.pack()
        # Cap height so it never exceeds screen height
        screen = Toolkit.getDefaultToolkit().getScreenSize()
        capped_h = min(dialog.getHeight() + 20, int(screen.height * 0.85))
        dialog.setSize(Dimension(680, capped_h))
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)
    
    def createSettingsPanel(self, parent_dialog):
        """Create advanced settings panel"""
        
        settings_panel = JPanel()
        settings_panel.setLayout(BoxLayout(settings_panel, BoxLayout.Y_AXIS))
        settings_panel.setBorder(TitledBorder("Settings"))
        
        # Advanced mode checkbox
        advanced_checkbox = JCheckBox("WARNING: Advanced / Experimental - may impact Burp performance")
        advanced_checkbox.setAlignmentX(0.0)
        advanced_checkbox.setSelected(self.advanced_mode)
        settings_panel.add(advanced_checkbox)
        
        settings_panel.add(Box.createVerticalStrut(6))
        
        # Max regex length selector
        length_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        length_label = JLabel("Max regex length:")
        length_panel.add(length_label)
        
        length_options = [50, 100, 150, 200, 300]
        length_combo = JComboBox([str(x) for x in length_options])
        
        # Set current value
        current_idx = 1  # Default 100
        try:
            current_idx = length_options.index(self.max_regex_length)
        except:
            pass
        length_combo.setSelectedIndex(current_idx)
        length_combo.setEnabled(self.advanced_mode)
        
        length_panel.add(length_combo)
        settings_panel.add(length_panel)
        
        # Advanced checkbox listener
        def onAdvancedToggle(event):
            enabled = advanced_checkbox.isSelected()
            length_combo.setEnabled(enabled)
            
            if not enabled:
                # Reset to default
                self.max_regex_length = self.DEFAULT_MAX_REGEX_LENGTH
                length_combo.setSelectedIndex(1)  # 100
                self.advanced_mode = False
            else:
                self.advanced_mode = True
        
        advanced_checkbox.addActionListener(onAdvancedToggle)
        
        # Length combo listener
        def onLengthChange(event):
            if not advanced_checkbox.isSelected():
                return
            
            selected = length_combo.getSelectedItem()
            new_length = int(selected)
            
            # Warning for 300
            if new_length == 300:
                result = JOptionPane.showConfirmDialog(
                    parent_dialog,
                    "WARNING: Increasing max regex length to 300 may cause high CPU usage,\n" +
                    "Burp UI freezes, or crashes when searching large responses.\n\n" +
                    "Proceed only if you understand the risk.",
                    "Performance Warning",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE
                )
                
                if result == JOptionPane.OK_OPTION:
                    self.max_regex_length = new_length
                else:
                    # Revert to 100
                    length_combo.setSelectedIndex(1)
                    self.max_regex_length = self.DEFAULT_MAX_REGEX_LENGTH
            else:
                self.max_regex_length = new_length
        
        length_combo.addActionListener(onLengthChange)
        
        return settings_panel
    
    def isSameCharType(self, char1, char2):
        """Check if two characters are of the same type"""
        if char1.isdigit() and char2.isdigit():
            return True
        if char1.isalpha() and char2.isalpha() and char1.isupper() == char2.isupper():
            return True
        if char1.isspace() and char2.isspace():
            return True
        if char1 == char2 and not (char1.isalnum() or char1.isspace()):
            return True
        return False
