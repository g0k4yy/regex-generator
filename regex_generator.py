from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import (JMenuItem, JPanel, JTextArea, JButton, JScrollPane, 
                         BoxLayout, JLabel, JDialog, JComboBox, JSeparator, 
                         SwingUtilities, JCheckBox, JOptionPane, Timer)
from javax.swing.border import EmptyBorder, TitledBorder
from java.awt import Toolkit, BorderLayout, Dimension, FlowLayout, Font
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
        print("Default max regex length: {}".format(self.max_regex_length))
    
    # ========================================================================
    # BURP INTEGRATION METHODS
    # ========================================================================
    
    def createMenuItems(self, invocation):
        """Create context menu items for selected text"""
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
        
        # Get the message based on context
        if context in (IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                       IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST):
            message = invocation.getSelectedMessages()[0].getRequest()
        elif context in (IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
                         IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE):
            message = invocation.getSelectedMessages()[0].getResponse()
        else:
            return None
        
        # Extract selected text using bounds
        start = selection_bounds[0]
        end = selection_bounds[1]
        
        selected_bytes = message[start:end]
        selected_text = self._helpers.bytesToString(selected_bytes)
        
        return selected_text
    
    def getSurroundingContext(self, invocation):
        """Get text before and after the selection for context"""
        selection_bounds = invocation.getSelectionBounds()
        context = invocation.getInvocationContext()
        
        # Get the message based on context
        if context in (IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                       IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST):
            message = invocation.getSelectedMessages()[0].getRequest()
        elif context in (IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
                         IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE):
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
    
    # ========================================================================
    # MAIN REGEX GENERATION LOGIC
    # ========================================================================
    
    def generateRegex(self, invocation, selected_text):
        """Generate regex patterns and show dialog"""
        
        # Get surrounding context
        context_before, context_after = self.getSurroundingContext(invocation)
        
        # Generate patterns
        exact_patterns = self.createExactPatterns(selected_text)
        pattern_variations = self.createPatternVariations(selected_text, context_before, context_after)
        default_patterns = self.createDefaultTextbookPatterns()
        
        # Show dialog on EDT
        def showDialog():
            self.showRegexDialog(selected_text, exact_patterns, pattern_variations, 
                                default_patterns, context_before, context_after)
        
        SwingUtilities.invokeLater(showDialog)
    
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
        """Create pattern variations with ReDoS safety"""
        
        variations = []
        pattern_set = set()  # For deduplication
        
        # Get context patterns
        prefix_pattern = self.extractContextPattern(context_before, is_before=True)
        suffix_pattern = self.extractContextPattern(context_after, is_before=False)
        
        in_json_quoted = prefix_pattern and re.search(r'"[\w-]+"\s*:\s*"$', prefix_pattern.replace('\\', ''))
        in_json_unquoted = prefix_pattern and re.search(r'"[\w-]+"\s*:\s*$', prefix_pattern.replace('\\', ''))
        in_html_attr = prefix_pattern and re.search(r'[\w-]+\s*=\s*"$', prefix_pattern.replace('\\', ''))
        
        # Add recommended patterns
        self._addRecommendedPatterns(variations, pattern_set, text, prefix_pattern, 
                                      suffix_pattern, in_json_quoted, in_html_attr)
        
        # Add type-based patterns
        if re.match(r'^https?://', text):
            self._addUrlPatterns(variations, pattern_set, text)
        
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', text):
            self._addEmailPatterns(variations, pattern_set, text)
        
        if len(text) > 5 and re.search(r'[a-zA-Z0-9]', text):
            self._addIdTokenPatterns(variations, pattern_set, text)
        
        if re.match(r'^\d+$', text):
            self._addNumericPatterns(variations, pattern_set, text)
        
        if '-' in text or '_' in text or '.' in text:
            self._addSeparatorPatterns(variations, pattern_set, text)
        
        return self._sortPatterns(variations)
    
    def createDefaultTextbookPatterns(self):
        """Create all default textbook patterns"""
        
        return [
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
    
    # ========================================================================
    # PATTERN GENERATION HELPER METHODS
    # ========================================================================
    
    def _addRecommendedPatterns(self, variations, pattern_set, text, prefix_pattern, 
                                suffix_pattern, in_json_quoted, in_html_attr):
        """Add recommended context-aware patterns"""
        
        # Exact with context
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
        
        # JSON field - any value
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
        
        # HTML attribute - any value
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
            domain_pattern = r'(https?://' + re.escape(domain) + r'[^\s"]{0,150})'
            
            if len(domain_pattern) <= self.max_regex_length:
                patterns.append({
                    'category': 'type',
                    'name': '[TYPE] URL - Same Domain',
                    'pattern': domain_pattern,
                    'description': 'URLs from ' + domain[:30] + '...'
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
        """Add separator-based patterns"""
        
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
    
    def _sortPatterns(self, variations):
        """Sort patterns by category priority"""
        priority = {'recommended': 0, 'type': 1, 'textbook': 2}
        return sorted(variations, key=lambda x: priority.get(x.get('category', 'textbook'), 3))
    
    # ========================================================================
    # SAFETY AND VALIDATION METHODS
    # ========================================================================
    
    def applySafetyLimits(self, pattern):
        """Apply ReDoS safety rules to pattern"""
        
        # Hard length limit
        if len(pattern) > self.HARD_MAX_REGEX_LENGTH:
            return pattern[:self.HARD_MAX_REGEX_LENGTH]
        
        # Detect and block dangerous patterns
        dangerous = [r'\.\*\.\*', r'\(\.\+\)\+', r'\(\.\*\)\+', r'\{0,\}']
        
        for danger in dangerous:
            if re.search(danger, pattern):
                return r'(.{1,100})'  # Safe fallback
        
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
    
    # ========================================================================
    # UI DIALOG METHODS
    # ========================================================================
    
    def showRegexDialog(self, selected_text, exact_patterns, pattern_variations, 
                       default_patterns, context_before, context_after):
        """Show regex dialog with all pattern options"""
        
        dialog = JDialog()
        dialog.setTitle("Regex Generator Pro")
        dialog.setModal(True)
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE)
        
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))
        main_panel.setBorder(EmptyBorder(15, 15, 15, 15))
        
        # Add context preview
        self._addContextPreview(main_panel, selected_text, context_before, context_after)
        
        # Add selected text display
        self._addSelectedTextDisplay(main_panel, selected_text)
        
        main_panel.add(JLabel(" "))
        main_panel.add(JSeparator())
        main_panel.add(JLabel(" "))
        
        # Add exact match section
        self._addExactMatchSection(main_panel, exact_patterns)
        
        main_panel.add(JLabel(" "))
        main_panel.add(JSeparator())
        main_panel.add(JLabel(" "))
        
        # Add pattern variations section
        if pattern_variations:
            self._addPatternVariationsSection(main_panel, pattern_variations)
            
            main_panel.add(JLabel(" "))
            main_panel.add(JSeparator())
            main_panel.add(JLabel(" "))
        
        # Add default patterns section
        self._addDefaultPatternsSection(main_panel, default_patterns)
        
        main_panel.add(JLabel(" "))
        main_panel.add(JSeparator())
        main_panel.add(JLabel(" "))
        
        # Add settings section
        settings_panel = self.createSettingsPanel(dialog)
        main_panel.add(settings_panel)
        
        main_panel.add(JLabel(" "))
        
        # Add close button
        self._addCloseButton(main_panel, dialog)
        
        # Wrap main panel in scroll pane so content is reachable on any screen size
        scroll_pane = JScrollPane(main_panel)
        scroll_pane.getVerticalScrollBar().setUnitIncrement(16)
        scroll_pane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        scroll_pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)

        # Configure dialog
        dialog.getContentPane().setLayout(BorderLayout())
        dialog.getContentPane().add(scroll_pane, BorderLayout.CENTER)

        # Size dialog relative to screen - cap at 90% of screen height
        screen_size = Toolkit.getDefaultToolkit().getScreenSize()
        dialog_width = min(730, int(screen_size.width * 0.90))
        dialog_height = min(int(screen_size.height * 0.90), 800)

        dialog.setSize(Dimension(dialog_width, dialog_height))
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)
    
    def _addContextPreview(self, panel, selected_text, context_before, context_after):
        """Add context preview section to panel"""
        if context_before or context_after:
            context_label = JLabel("Context:")
            context_label.setFont(Font(context_label.getFont().getName(), Font.BOLD, 12))
            panel.add(context_label)

            preview_before = context_before[-30:] if len(context_before) > 30 else context_before
            preview_after = context_after[:30] if len(context_after) > 30 else context_after
            context_preview = preview_before + "[" + selected_text + "]" + preview_after

            context_area = JTextArea(context_preview)
            context_area.setEditable(False)
            context_area.setLineWrap(True)
            context_area.setRows(2)
            panel.add(JScrollPane(context_area))
            panel.add(JLabel(" "))

    def _addSelectedTextDisplay(self, panel, selected_text):
        """Add selected text display section to panel"""
        selected_label = JLabel("Selected Text:")
        selected_label.setFont(Font(selected_label.getFont().getName(), Font.BOLD, 12))
        panel.add(selected_label)

        selected_area = JTextArea(selected_text[:200])
        selected_area.setEditable(False)
        selected_area.setLineWrap(True)
        selected_area.setRows(2)
        panel.add(JScrollPane(selected_area))
    
    def _addExactMatchSection(self, panel, exact_patterns):
        """Add exact match patterns section to panel"""
        exact_label = JLabel("1. Exact Match Options:")
        exact_label.setFont(Font(exact_label.getFont().getName(), Font.BOLD, 13))
        panel.add(exact_label)
        panel.add(JLabel(" "))

        # Dropdown
        dropdown_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        dropdown_panel.add(JLabel("Select type:"))

        exact_dropdown = JComboBox([p['name'] for p in exact_patterns])
        dropdown_panel.add(exact_dropdown)
        panel.add(dropdown_panel)

        panel.add(JLabel(" "))

        # Description and pattern area
        exact_desc = JLabel("   " + exact_patterns[0]['description'])
        panel.add(exact_desc)
        panel.add(JLabel(" "))

        exact_area = JTextArea(exact_patterns[0]['pattern'])
        exact_area.setEditable(True)
        exact_area.setLineWrap(True)
        exact_area.setRows(2)
        panel.add(JScrollPane(exact_area))

        # Copy button
        exact_button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        exact_copy_btn = JButton("Copy to Clipboard")

        def copyExact(event):
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(exact_area.getText()), None)
            exact_copy_btn.setText("Copied!")

            def reset(e):
                exact_copy_btn.setText("Copy to Clipboard")
            timer = Timer(1500, reset)
            timer.setRepeats(False)
            timer.start()

        exact_copy_btn.addActionListener(copyExact)
        exact_button_panel.add(exact_copy_btn)
        panel.add(exact_button_panel)

        # Dropdown listener
        def onExactChange(event):
            idx = exact_dropdown.getSelectedIndex()
            if 0 <= idx < len(exact_patterns):
                p = exact_patterns[idx]
                exact_area.setText(p['pattern'])
                exact_desc.setText("   " + p['description'])

        exact_dropdown.addActionListener(onExactChange)
    
    def _addPatternVariationsSection(self, panel, pattern_variations):
        """Add pattern variations section to panel"""
        pattern_label = JLabel("2. Context-Based Pattern Variations:")
        pattern_label.setFont(Font(pattern_label.getFont().getName(), Font.BOLD, 13))
        panel.add(pattern_label)
        panel.add(JLabel(" "))

        # Dropdown
        dropdown_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        dropdown_panel.add(JLabel("Select pattern:"))

        dropdown = JComboBox([var['name'] for var in pattern_variations])
        dropdown_panel.add(dropdown)
        panel.add(dropdown_panel)

        panel.add(JLabel(" "))

        # Description and pattern area
        desc_label = JLabel("   " + pattern_variations[0]['description'])
        panel.add(desc_label)
        panel.add(JLabel(" "))

        pattern_area = JTextArea(pattern_variations[0]['pattern'])
        pattern_area.setEditable(True)
        pattern_area.setLineWrap(True)
        pattern_area.setRows(2)
        panel.add(JScrollPane(pattern_area))

        # Copy button
        pattern_button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        pattern_copy_btn = JButton("Copy to Clipboard")

        def copyPattern(event):
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(pattern_area.getText()), None)
            pattern_copy_btn.setText("Copied!")

            def reset(e):
                pattern_copy_btn.setText("Copy to Clipboard")
            timer = Timer(1500, reset)
            timer.setRepeats(False)
            timer.start()

        pattern_copy_btn.addActionListener(copyPattern)
        pattern_button_panel.add(pattern_copy_btn)
        panel.add(pattern_button_panel)

        # Dropdown listener
        def onDropdownChange(event):
            idx = dropdown.getSelectedIndex()
            if 0 <= idx < len(pattern_variations):
                var = pattern_variations[idx]
                pattern_area.setText(var['pattern'])
                desc_label.setText("   " + var['description'])

        dropdown.addActionListener(onDropdownChange)
    
    def _addDefaultPatternsSection(self, panel, default_patterns):
        """Add default textbook patterns section to panel"""
        default_label = JLabel("3. Default Textbook Patterns:")
        default_label.setFont(Font(default_label.getFont().getName(), Font.BOLD, 13))
        panel.add(default_label)
        panel.add(JLabel(" "))

        # Dropdown
        dropdown_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        dropdown_panel.add(JLabel("Select pattern:"))

        default_dropdown = JComboBox([p['name'] for p in default_patterns])
        dropdown_panel.add(default_dropdown)
        panel.add(dropdown_panel)

        panel.add(JLabel(" "))

        # Description and pattern area
        default_desc = JLabel("   " + default_patterns[0]['description'])
        panel.add(default_desc)
        panel.add(JLabel(" "))

        default_area = JTextArea(default_patterns[0]['pattern'])
        default_area.setEditable(True)
        default_area.setLineWrap(True)
        default_area.setRows(2)
        panel.add(JScrollPane(default_area))

        # Copy button
        default_button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        default_copy_btn = JButton("Copy to Clipboard")

        def copyDefault(event):
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(default_area.getText()), None)
            default_copy_btn.setText("Copied!")

            def reset(e):
                default_copy_btn.setText("Copy to Clipboard")
            timer = Timer(1500, reset)
            timer.setRepeats(False)
            timer.start()

        default_copy_btn.addActionListener(copyDefault)
        default_button_panel.add(default_copy_btn)
        panel.add(default_button_panel)

        # Dropdown listener
        def onDefaultChange(event):
            idx = default_dropdown.getSelectedIndex()
            if 0 <= idx < len(default_patterns):
                p = default_patterns[idx]
                default_area.setText(p['pattern'])
                default_desc.setText("   " + p['description'])

        default_dropdown.addActionListener(onDefaultChange)
    
    def _addCloseButton(self, panel, dialog):
        """Add close button to panel"""
        bottom_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        
        def closeDialog(event):
            dialog.dispose()
        
        close_button = JButton("Close")
        close_button.addActionListener(closeDialog)
        bottom_panel.add(close_button)
        panel.add(bottom_panel)
    
    def createSettingsPanel(self, parent_dialog):
        """Create advanced settings panel"""
        
        settings_panel = JPanel()
        settings_panel.setLayout(BoxLayout(settings_panel, BoxLayout.Y_AXIS))
        settings_panel.setBorder(TitledBorder("Settings"))
        
        # Advanced mode checkbox
        advanced_checkbox = JCheckBox("WARNING: Advanced / Experimental - may impact Burp performance")
        advanced_checkbox.setSelected(self.advanced_mode)
        settings_panel.add(advanced_checkbox)
        
        settings_panel.add(JLabel(" "))
        
        # Max regex length selector
        length_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        length_panel.add(JLabel("Max regex length:"))
        
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
                    print("Max regex length set to: {}".format(new_length))
                else:
                    length_combo.setSelectedIndex(1)
                    self.max_regex_length = self.DEFAULT_MAX_REGEX_LENGTH
            else:
                self.max_regex_length = new_length
                print("Max regex length set to: {}".format(new_length))
        
        length_combo.addActionListener(onLengthChange)
        
        return settings_panel
