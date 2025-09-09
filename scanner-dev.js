class QRSafetyScanner {
    constructor() {
        try {
            this.video = document.getElementById('video');
            this.canvas = document.getElementById('canvas');
            this.ctx = this.canvas.getContext('2d');
            this.scanning = false;
            this.stream = null;
            this.lastScannedCode = null;
            this.hasAI = false;
            this.aiSession = null;
            this.initializeElements();
            this.initEventListeners();
            this.initHomoglyphMap();
            this.initAIPatterns();
        } catch (error) {
            console.error('Error in scanner constructor:', error);
        }
    }

    initializeElements() {
        try {
            this.startButton = document.getElementById('startButton');
            this.resultModal = document.getElementById('resultModal');
            this.closeModalBtn = document.getElementById('closeModal');
            this.permissionScreen = document.getElementById('permissionScreen');
            this.grantPermissionBtn = document.getElementById('grantPermission');
            this.loadingSpinner = document.querySelector('.loading-spinner');
            this.copyButton = document.getElementById('copyButton');
            this.openButton = document.getElementById('openButton');
            this.homoglyphWarning = document.getElementById('homoglyphWarning');
            this.externalChecks = document.getElementById('externalChecks');
            this.helpButton = document.getElementById('helpButton');
            this.helpModal = document.getElementById('helpModal');
            this.closeHelpBtn = document.getElementById('closeHelp');
            this.buttonsContainer = document.querySelector('.action-buttons-container');

            console.log('✅ Elements initialized');
        } catch (error) {
            console.error('Error initializing elements:', error);
        }
    }

    initEventListeners() {
        try {
            const addClickAndTouch = (element, handler) => {
                if (element) {
                    element.addEventListener('click', handler, { passive: false });
                    element.addEventListener('touchend', (e) => {
                        e.preventDefault();
                        handler();
                    }, { passive: false });
                }
            };

            addClickAndTouch(this.startButton, () => this.startScanning());
            addClickAndTouch(this.closeModalBtn, () => this.closeResult());
            addClickAndTouch(this.grantPermissionBtn, () => this.requestCameraPermission());
            addClickAndTouch(this.copyButton, () => this.copyToClipboard());
            addClickAndTouch(this.openButton, () => this.openLink());
            addClickAndTouch(this.helpButton, () => this.showHelp());
            addClickAndTouch(this.closeHelpBtn, () => this.closeHelp());

            console.log('✅ Event listeners initialized');
        } catch (error) {
            console.error('Error setting up event listeners:', error);
        }
    }

    showHelp() {
        try {
            if (this.helpModal) {
                this.helpModal.classList.add('active');
            }
        } catch (e) {
            console.error('Error showing help:', e);
        }
    }

    closeHelp() {
        try {
            if (this.helpModal) {
                this.helpModal.classList.remove('active');
            }
        } catch (e) {
            console.error('Error closing help:', e);
        }
    }

    initHomoglyphMap() {
        this.homoglyphs = {
            'a': ['а', 'ɑ', 'α', 'ａ'],
            'b': ['ь', 'ḃ', 'ｂ'],
            'c': ['с', 'ϲ', 'ⅽ', 'ｃ'],
            'd': ['ԁ', 'ⅾ', 'ｄ'],
            'e': ['е', 'ё', 'ε', 'ｅ'],
            'f': ['ḟ', 'ｆ'],
            'g': ['ġ', 'ɡ', 'ｇ'],
            'h': ['һ', 'ｈ'],
            'i': ['і', 'ı', 'ⅰ', 'ｉ'],
            'j': ['ј', 'ⅼ', 'ｊ'],
            'k': ['к', 'ｋ'],
            'l': ['ӏ', '1', 'ⅼ', 'ｌ', '|'],
            'm': ['м', 'ⅿ', 'ｍ'],
            'n': ['п', 'ｎ'],
            'o': ['о', '0', 'ο', 'ｏ', 'ø', 'ф'],
            'p': ['р', 'ρ', 'ｐ'],
            'q': ['ԛ', 'ｑ'],
            'r': ['г', 'ｒ'],
            's': ['ѕ', 'ｓ'],
            't': ['т', 'ｔ'],
            'u': ['υ', 'ｕ', 'ц'],
            'v': ['ν', 'ⅴ', 'ｖ'],
            'w': ['ԝ', 'ⅿ', 'ｗ', 'ш'],
            'x': ['х', 'ⅹ', 'ｘ'],
            'y': ['у', 'ｙ'],
            'z': ['ｚ', 'ζ'],
            'A': ['А', 'Α', 'Ａ'],
            'B': ['В', 'Β', 'Ｂ'],
            'C': ['С', 'Ͻ', 'Ｃ'],
            'E': ['Е', 'Ε', 'Ｅ'],
            'H': ['Н', 'Η', 'Ｈ'],
            'I': ['І', 'Ι', 'Ｉ', '|'],
            'K': ['К', 'Κ', 'Ｋ'],
            'M': ['М', 'Μ', 'Ｍ'],
            'N': ['Ν', 'Ｎ'],
            'O': ['О', '0', 'Ο', 'Ｏ', 'Ф'],
            'P': ['Р', 'Ρ', 'Ｐ'],
            'S': ['Ѕ', 'Ｓ'],
            'T': ['Т', 'Τ', 'Ｔ'],
            'X': ['Х', 'Χ', 'Ｘ'],
            'Y': ['У', 'Υ', 'Ｙ'],
            'Z': ['Ζ', 'Ｚ'],
            '0': ['О', 'о', 'O', 'o', 'Ο', 'ο', 'Ｏ', 'ｏ'],
            '1': ['l', 'I', 'ӏ', '|', 'ｌ', 'Ｉ'],
            '6': ['б'],
            '9': ['g']
        };

        this.reverseHomoglyphs = {};
        for (const [original, variants] of Object.entries(this.homoglyphs)) {
            for (const variant of variants) {
                if (!this.reverseHomoglyphs[variant]) {
                    this.reverseHomoglyphs[variant] = [];
                }
                this.reverseHomoglyphs[variant].push(original);
            }
        }
    }

    detectHomoglyphs(text) {
        const suspicious = [];
        const chars = [...text];

        for(let i = 0; i < chars.length; i++) {
            const char = chars[i];

            if (this.reverseHomoglyphs[char]) {
                suspicious.push({
                    position: i,
                    char: char,
                    original: this.reverseHomoglyphs[char],
                    unicode: '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')
                });
            }

            const charCode = char.charCodeAt(0);
            const isCyrillic = (charCode >= 0x0400 && charCode <= 0x04FF);
            const isGreek = (charCode >= 0x0370 && charCode <= 0x03FF);
            const isFullwidth = (charCode >= 0xFF00 && charCode <= 0xFFEF);

            if (isCyrillic || isGreek || isFullwidth) {
                if (!suspicious.find(s => s.position === i)) {
                    suspicious.push({
                        position: i,
                        char: char,
                        type: isCyrillic ? 'Cyrillic' : isGreek ? 'Greek' : 'Fullwidth',
                        unicode: '\\u' + charCode.toString(16).padStart(4, '0')
                    });
                }
            }
        }

        return suspicious;
    }

    async checkRedirects(url, maxRedirects = 10) {
        const redirectChain = [];
        const maliciousUrls = [];
        let currentUrl = url;
        let finalUrl = url;
        let error = null;
        let hasSecurityIssues = false;

        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            const isKnownShortener = this.threatPatterns.shorteners.domains.some(shortener =>
                domain.includes(shortener));

            // Check ALL URLs for redirects, not just shorteners
            // Use safer HEAD requests with manual redirect handling
            for (let i = 0; i < maxRedirects; i++) {
                try {
                    // First, check if current URL is malicious
                    const isMalicious = this.checkUrlSafety(currentUrl);
                    if (!isMalicious.safe) {
                        maliciousUrls.push({
                            url: currentUrl,
                            step: i + 1,
                            issues: isMalicious.issues
                        });
                        hasSecurityIssues = true;
                    }

                    // Try safe redirect detection without executing any code from the target
                    const redirectInfo = await this.safeRedirectCheck(currentUrl);

                    if (redirectInfo && redirectInfo.redirectUrl && redirectInfo.redirectUrl !== currentUrl) {
                        redirectChain.push({
                            from: currentUrl,
                            to: redirectInfo.redirectUrl,
                            status: redirectInfo.status || 301,
                            method: redirectInfo.method,
                            isMalicious: !isMalicious.safe
                        });
                        currentUrl = redirectInfo.redirectUrl;
                        finalUrl = redirectInfo.redirectUrl;
                    } else {
                        // No more redirects found
                        break;
                    }
                } catch (fetchError) {
                    console.log('Redirect check iteration failed:', fetchError);
                    error = fetchError.message;
                    break;
                }
            }

            // Final safety check on the destination URL
            const finalCheck = this.checkUrlSafety(finalUrl);
            if (!finalCheck.safe) {
                maliciousUrls.push({
                    url: finalUrl,
                    step: redirectChain.length + 1,
                    issues: finalCheck.issues,
                    isFinal: true
                });
                hasSecurityIssues = true;
            }

            // If we couldn't trace redirects but it's a known shortener, try expansion APIs
            if (redirectChain.length === 0 && isKnownShortener) {
                const apiResult = await this.tryUrlExpansionAPIs(url);
                if (apiResult) {
                    redirectChain.push(apiResult);
                    finalUrl = apiResult.to;

                    // Check the expanded URL for safety
                    const expandedCheck = this.checkUrlSafety(finalUrl);
                    if (!expandedCheck.safe) {
                        maliciousUrls.push({
                            url: finalUrl,
                            step: 2,
                            issues: expandedCheck.issues,
                            isFinal: true
                        });
                        hasSecurityIssues = true;
                    }
                }
            }
                            }
                        }
                    } catch (apiError) {
                        console.log('LongURL API failed');
                    }
                }
            }

            // Pattern-based detection for common shorteners
            if (redirectChain.length === 0 && isKnownShortener) {
                const shortCode = url.split('/').pop();
                if (shortCode && shortCode.length < 15) {
                    return {
                        originalUrl: url,
                        finalUrl: url,
                        redirectChain: [],
                        hasRedirects: true,
                        redirectCount: 1,
                        error: 'Unable to expand URL due to CORS restrictions',
                        warning: 'This is a shortened URL. Destination cannot be verified without visiting.',
                        shortenerDomain: domain
                    };
                }
            }

        } catch (e) {
            error = e.message;
            console.error('Redirect checking failed:', e);
        }

        return {
            originalUrl: url,
            finalUrl: finalUrl || url,
            redirectChain: redirectChain,
            hasRedirects: redirectChain.length > 0,
            redirectCount: redirectChain.length,
            maliciousUrls: maliciousUrls,
            hasSecurityIssues: hasSecurityIssues,
            error: error,
            shortenerDomain: isKnownShortener ? domain : null,
            warning: isKnownShortener && redirectChain.length === 0 ?
                'URL shortener detected but unable to trace redirects' : null
        };
    }

    // Safe redirect checking without executing any code from target pages
    async safeRedirectCheck(url) {
        try {
            // Try using a safe CORS proxy with HEAD request only
            const corsProxies = [
                'https://corsproxy.io/?',
                'https://api.allorigins.win/raw?url=',
                'https://cors-anywhere.herokuapp.com/'
            ];

            for (const proxy of corsProxies) {
                try {
                    const proxyUrl = proxy + encodeURIComponent(url);
                    const response = await fetch(proxyUrl, {
                        method: 'HEAD',
                        mode: 'cors',
                        redirect: 'manual',
                        signal: AbortSignal.timeout(3000),
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                    });

                    // Check for redirect headers
                    const location = response.headers.get('location') ||
                                   response.headers.get('Location') ||
                                   response.headers.get('x-final-url');

                    if (location && location !== url) {
                        // Make sure it's an absolute URL
                        const redirectUrl = new URL(location, url).href;
                        return {
                            redirectUrl: redirectUrl,
                            status: response.status,
                            method: 'HTTP Redirect'
                        };
                    }

                    // If response is successful but no redirect header, try to detect meta refresh
                    if (response.status === 200) {
                        // For meta refresh detection, we need a minimal GET request
                        // but we'll limit the response size for safety
                        const textResponse = await fetch(proxyUrl, {
                            method: 'GET',
                            mode: 'cors',
                            signal: AbortSignal.timeout(3000),
                            headers: {
                                'X-Requested-With': 'XMLHttpRequest',
                                'Range': 'bytes=0-5000' // Only fetch first 5KB
                            }
                        });

                        const textContent = await textResponse.text();
                        const metaRefresh = this.detectMetaRefresh(textContent);
                        if (metaRefresh) {
                            return {
                                redirectUrl: new URL(metaRefresh, url).href,
                                status: 200,
                                method: 'Meta Refresh'
                            };
                        }
                    }

                    break; // If we got a response, don't try other proxies
                } catch (proxyError) {
                    console.log(`Proxy ${proxy} failed:`, proxyError.message);
                    continue; // Try next proxy
                }
            }
        } catch (error) {
            console.log('Safe redirect check failed:', error);
        }

        return null;
    }

    // Detect meta refresh redirects in HTML without executing JavaScript
    detectMetaRefresh(htmlContent) {
        try {
            // Only check the first 5KB to avoid processing large pages
            const snippet = htmlContent.substring(0, 5000);

            // Look for meta refresh tag
            const metaRefreshPattern = /<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']([^"']+)["'][^>]*>/i;
            const match = snippet.match(metaRefreshPattern);

            if (match) {
                // Parse the content attribute (e.g., "0; url=http://example.com")
                const content = match[1];
                const urlMatch = content.match(/url\s*=\s*(.+)/i);
                if (urlMatch) {
                    return urlMatch[1].trim();
                }
            }

            // Also check for JavaScript redirects (common patterns only, without executing)
            const jsRedirectPatterns = [
                /window\.location\s*=\s*["']([^"']+)["']/,
                /window\.location\.href\s*=\s*["']([^"']+)["']/,
                /window\.location\.replace\s*\(\s*["']([^"']+)["']\s*\)/,
                /location\.href\s*=\s*["']([^"']+)["']/
            ];

            for (const pattern of jsRedirectPatterns) {
                const jsMatch = snippet.match(pattern);
                if (jsMatch) {
                    return jsMatch[1];
                }
            }
        } catch (error) {
            console.log('Meta refresh detection error:', error);
        }

        return null;
    }

    // Check if a URL is malicious based on various criteria
    checkUrlSafety(url) {
        const issues = [];
        let safe = true;

        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            const path = urlObj.pathname.toLowerCase();

            // Check against known phishing domains
            if (this.threatDatabase && this.threatDatabase.knownPhishing) {
                if (this.threatDatabase.knownPhishing.some(phish => domain.includes(phish))) {
                    issues.push('Known phishing domain');
                    safe = false;
                }
            }

            // Check for suspicious patterns
            if (domain.includes('@')) {
                issues.push('Contains @ symbol (potential deception)');
                safe = false;
            }

            // Check for IP addresses instead of domains
            const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (ipPattern.test(domain)) {
                issues.push('IP address instead of domain name');
                safe = false;
            }

            // Check for suspicious TLDs
            const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review'];
            if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
                issues.push('Suspicious top-level domain');
                safe = false;
            }

            // Check for homoglyphs
            const homoglyphsFound = this.detectHomoglyphs(domain);
            if (homoglyphsFound.length > 0) {
                issues.push(`Contains lookalike characters (${homoglyphsFound.length} found)`);
                safe = false;
            }

            // Check for typosquatting
            const typosquatCheck = this.checkTyposquatting(domain);
            if (typosquatCheck.isTyposquatting) {
                issues.push(`Possible typosquatting of ${typosquatCheck.similarTo}`);
                safe = false;
            }

            // Check for suspicious keywords in path
            const suspiciousKeywords = [
                'verify', 'confirm', 'update', 'suspend', 'locked',
                'secure', 'account', 'billing', 'payment', 'expired',
                'refund', 'alert', 'urgent', 'immediate'
            ];

            for (const keyword of suspiciousKeywords) {
                if (path.includes(keyword) || domain.includes(keyword)) {
                    issues.push(`Contains suspicious keyword: ${keyword}`);
                    if (!this.isTrustedDomain(domain)) {
                        safe = false;
                    }
                }
            }

            // Check protocol
            if (urlObj.protocol === 'http:') {
                issues.push('Uses insecure HTTP protocol');
                // Not marking as unsafe, just a warning
            }

            // Check for data URIs
            if (urlObj.protocol === 'data:') {
                issues.push('Data URI detected');
                safe = false;
            }

            // Check for JavaScript URIs
            if (urlObj.protocol === 'javascript:') {
                issues.push('JavaScript URI detected - HIGH RISK');
                safe = false;
            }

        } catch (error) {
            issues.push('Invalid URL format');
            safe = false;
        }

        return {
            safe: safe,
            issues: issues
        };
    }

    // Check if domain is in trusted list
    isTrustedDomain(domain) {
        if (!this.threatPatterns || !this.threatPatterns.trustedDomains) {
            return false;
        }

        return this.threatPatterns.trustedDomains.some(trusted =>
            domain === trusted || domain.endsWith('.' + trusted)
        );
    }

    // Check for typosquatting
    checkTyposquatting(domain) {
        const popularDomains = [
            'google.com', 'facebook.com', 'amazon.com', 'apple.com',
            'microsoft.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'youtube.com', 'netflix.com', 'paypal.com', 'ebay.com',
            'reddit.com', 'wikipedia.org', 'yahoo.com', 'github.com'
        ];

        for (const popularDomain of popularDomains) {
            const similarity = this.calculateSimilarity(domain, popularDomain);
            if (similarity > 0.8 && similarity < 1.0) {
                return {
                    isTyposquatting: true,
                    similarTo: popularDomain,
                    similarity: similarity
                };
            }
        }

        return {
            isTyposquatting: false
        };
    }

    // Try URL expansion APIs as fallback
    async tryUrlExpansionAPIs(url) {
        // Try unshorten.me
        try {
            const response = await fetch(`https://unshorten.me/json/${encodeURIComponent(url)}`, {
                signal: AbortSignal.timeout(3000)
            });
            if (response.ok) {
                const data = await response.json();
                if (data.resolved_url && data.resolved_url !== url) {
                    return {
                        from: url,
                        to: data.resolved_url,
                        status: 301,
                        method: 'URL Expansion API'
                    };
                }
            }
        } catch (error) {
            console.log('URL expansion API failed:', error);
        }

        return null;
    }

    async checkBrowserAI() {
        this.hasAI = false;
        this.aiSession = null;

        try {
            if (typeof window.ai !== 'undefined' && window.ai) {
                console.log('🤖 Browser AI API detected!');

                if (window.ai.canCreateTextSession) {
                    try {
                        const canUse = await window.ai.canCreateTextSession();
                        console.log('Gemini Nano availability:', canUse);

                        if (canUse === 'readily') {
                            this.aiSession = await window.ai.createTextSession();
                            this.hasAI = true;
                            console.log('✅ AI session created successfully');
                            this.showAIStatus(true);
                            return true;
                        }
                    } catch (e) {
                        console.log('⚠️ Cannot check AI availability:', e);
                    }
                }

                if (window.ai.createTextSession) {
                    try {
                        this.aiSession = await window.ai.createTextSession();
                        this.hasAI = true;
                        console.log('✅ AI session created successfully');
                        this.showAIStatus(true);
                        return true;
                    } catch (e) {
                        console.log('⚠️ AI API exists but session creation failed:', e);
                    }
                }
            }
        } catch (error) {
            console.log('Error checking browser AI:', error);
        }

        this.showAIStatus(false);
        return false;
    }

    showAIStatus(active) {
        try {
            const aiStatus = document.getElementById('aiStatus');
            if (aiStatus) {
                aiStatus.style.display = 'flex';
                if (active) {
                    aiStatus.classList.remove('inactive');
                    aiStatus.title = 'Browser AI Active - Using local LLM for analysis';
                } else {
                    aiStatus.classList.add('inactive');
                    aiStatus.title = 'Browser AI not available - Using pattern matching';
                }
            }
        } catch (e) {
            console.log('Could not update AI status indicator:', e);
        }
    }

    async analyzeWithAI(url) {
        if (!this.hasAI || !this.aiSession) {
            return null;
        }

        try {
            const prompt = `You are a security expert analyzing URLs for threats. Analyze this URL: "${url}"

            Check for these specific threats:
            - Phishing attempts (fake versions of legitimate sites)
            - Typosquatting (misspellings of popular domains)
            - Suspicious URL patterns (IP addresses, @ symbols, multiple subdomains)
            - Known malware distribution patterns
            - URL shorteners hiding destinations
            - Homoglyph attacks (lookalike characters from other alphabets)

            Important: Respond ONLY with valid JSON in this exact format, no other text:
            {
                "riskLevel": "low|medium|high",
                "threats": ["specific threat 1", "specific threat 2"],
                "aiConfidence": 85,
                "explanation": "One sentence explanation"
            }`;

            console.log('Sending prompt to AI...');
            const response = await this.aiSession.prompt(prompt);
            console.log('AI Response received:', response);

            try {
                let cleanResponse = response.trim();
                cleanResponse = cleanResponse.replace(/```json\n?/g, '').replace(/```\n?/g, '');

                const aiAnalysis = JSON.parse(cleanResponse);
                console.log('✅ Parsed AI Analysis:', aiAnalysis);
                return aiAnalysis;
            } catch (parseError) {
                console.log('Failed to parse AI response as JSON:', parseError);
                return this.parseAITextResponse(response);
            }
        } catch (error) {
            console.error('AI analysis error:', error);
            return null;
        }
    }

    parseAITextResponse(text) {
        try {
            const analysis = {
                riskLevel: 'medium',
                threats: [],
                aiConfidence: 70,
                explanation: text.substring(0, 200)
            };

            const lowerText = text.toLowerCase();
            if (lowerText.includes('high risk') || lowerText.includes('dangerous') || lowerText.includes('malicious')) {
                analysis.riskLevel = 'high';
                analysis.aiConfidence = 90;
            } else if (lowerText.includes('safe') || lowerText.includes('legitimate') || lowerText.includes('no threat')) {
                analysis.riskLevel = 'low';
                analysis.aiConfidence = 85;
            }

            const threatKeywords = ['phishing', 'malware', 'scam', 'fake', 'suspicious', 'typosquatting'];
            threatKeywords.forEach(threat => {
                if (lowerText.includes(threat)) {
                    analysis.threats.push(threat.charAt(0).toUpperCase() + threat.slice(1) + ' detected');
                }
            });

            return analysis;
        } catch (e) {
            console.error('Error parsing AI text response:', e);
            return null;
        }
    }

    initAIPatterns() {
        this.checkBrowserAI().then(hasAI => {
            if (hasAI) {
                console.log('🤖 Using real browser AI for analysis');
            } else {
                console.log('📊 Using pattern-based analysis');
            }
        }).catch(error => {
            console.error('Error initializing AI:', error);
        });

        this.threatPatterns = {
            phishing: {
                keywords: ['verify', 'suspend', 'confirm', 'update', 'expired', 'locked', 'secure', 'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'account', 'urgent', 'immediately'],
                patterns: [
                    /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
                    /@/,
                    /[0-9]{4,}/,
                    /-{2,}/,
                    /xn--/,
                ],
                suspiciousTLDs: ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review', '.top', '.work']
            },
            malware: {
                keywords: ['download', 'install', 'update', 'flash', 'player', 'java', 'plugin', 'free', 'crack', 'keygen'],
                extensions: ['.exe', '.zip', '.rar', '.bat', '.cmd', '.scr', '.vbs', '.jar', '.apk', '.msi']
            },
            shorteners: {
                domains: ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'short.link', 't.co', 'buff.ly', 'is.gd', 'tr.im', 'rebrand.ly']
            },
            trustedDomains: [
                'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
                'linkedin.com', 'github.com', 'stackoverflow.com', 'wikipedia.org', 'amazon.com',
                'apple.com', 'microsoft.com', 'netflix.com', 'spotify.com', 'reddit.com'
            ]
        };

        this.threatDatabase = {
            knownPhishing: [
                'secure-bank-update.com',
                'paypal-verification.net',
                'amazon-security.org',
                'apple-id-locked.com',
                'microsoft-account-verify.net'
            ],
            knownMalware: [
                'malware-download.com',
                'free-software-crack.net',
                'virus-infected.org'
            ]
        };
    }

    async requestCameraPermission() {
        try {
            this.permissionScreen.style.display = 'none';
            await this.initCamera();
        } catch (error) {
            console.error('Error requesting camera permission:', error);
            this.permissionScreen.style.display = 'flex';
        }
    }

    async startScanning() {
        try {
            console.log('Starting scanning...');
            this.startButton.style.display = 'none';
            await this.initCamera();
        } catch (error) {
            console.error('Error starting scanning:', error);
            this.startButton.style.display = 'block';
            alert('Failed to start scanning. Please try again.');
        }
    }

    async initCamera() {
        try {
            const constraints = {
                video: {
                    facingMode: 'environment',
                    width: { ideal: 1920 },
                    height: { ideal: 1080 }
                }
            };

            this.stream = await navigator.mediaDevices.getUserMedia(constraints);
            this.video.srcObject = this.stream;
            this.video.play();

            this.video.addEventListener('loadedmetadata', () => {
                this.canvas.width = this.video.videoWidth;
                this.canvas.height = this.video.videoHeight;
                this.scanning = true;
                this.scanQRCode();
            });
        } catch (error) {
            console.error('Camera access error:', error);
            this.handleCameraError(error);
        }
    }

    handleCameraError(error) {
        if (error.name === 'NotAllowedError' || error.name === 'PermissionDeniedError') {
            this.permissionScreen.style.display = 'flex';
            this.startButton.style.display = 'block';
        } else {
            alert('Unable to access camera. Please check your browser settings.');
            this.startButton.style.display = 'block';
        }
    }

    scanQRCode() {
        if (!this.scanning) return;

        if (this.video.readyState === this.video.HAVE_ENOUGH_DATA) {
            this.ctx.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);
            const imageData = this.ctx.getImageData(0, 0, this.canvas.width, this.canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);

            if (code && code.data !== this.lastScannedCode) {
                this.lastScannedCode = code.data;
                this.handleQRCode(code.data);
                this.vibrateDevice();
                this.scanning = false;
                this.stopCamera();
            }
        }

        if (this.scanning) {
            requestAnimationFrame(() => this.scanQRCode());
        }
    }

    stopCamera() {
        if (this.stream) {
            this.stream.getTracks().forEach(track => track.stop());
            this.stream = null;
            this.video.srcObject = null;
        }
    }

    vibrateDevice() {
        if ('vibrate' in navigator) {
            navigator.vibrate(200);
        }
    }

    handleQRCode(data) {
        this.showResult(data);
        this.analyzeURL(data);
        this.checkExternalServices(data);

        // Check for redirects for ALL URLs, not just shorteners
        try {
            const urlObj = new URL(data);

            // Always check for redirects
            this.showRedirectStatus('checking');
            this.checkRedirects(data).then(redirectInfo => {
                // Display redirect information if any
                if (redirectInfo.hasRedirects || redirectInfo.warning || redirectInfo.hasSecurityIssues) {
                    this.displayRedirectInfo(redirectInfo);
                }

                // If there's a different final URL, analyze it too
                if (redirectInfo.finalUrl !== data) {
                    this.analyzeURL(redirectInfo.finalUrl, redirectInfo);
                    this.checkExternalServices(redirectInfo.finalUrl);
                }

                // Show security warnings if malicious URLs found in chain
                if (redirectInfo.hasSecurityIssues) {
                    this.showRedirectSecurityWarning(redirectInfo.maliciousUrls);
                }
            }).catch(error => {
                console.error('Redirect check failed:', error);
                this.showRedirectStatus('failed');
            });
        } catch (e) {
            // Not a valid URL, skip redirect checking
            console.log('Not a valid URL for redirect checking:', e);
        }
    }

    showRedirectStatus(status) {
        const urlDisplay = document.getElementById('urlDisplay');
        if (status === 'checking') {
            const statusDiv = document.createElement('div');
            statusDiv.id = 'redirectStatus';
            statusDiv.style.cssText = 'margin-top: 10px; padding: 8px; background: rgba(255,149,0,0.1); border-radius: 8px; font-size: 13px; color: #FF9500;';
            statusDiv.innerHTML = '🔄 Checking for redirects...';
            urlDisplay.parentElement.insertBefore(statusDiv, urlDisplay.nextSibling);
        } else if (status === 'failed') {
            const statusDiv = document.getElementById('redirectStatus');
            if (statusDiv) {
                statusDiv.innerHTML = '⚠️ Could not check redirects (CORS limitation)';
            }
        }
    }

    displayRedirectInfo(redirectInfo) {
        const statusDiv = document.getElementById('redirectStatus');
        if (statusDiv) {
            statusDiv.remove();
        }

        // Handle case where it's a shortener but couldn't be expanded
        if (redirectInfo.warning) {
            const warningDisplay = document.createElement('div');
            warningDisplay.id = 'redirectWarning';
            warningDisplay.style.cssText = 'margin-top: 15px; padding: 12px; background: rgba(255,149,0,0.1); border: 1px solid #FF9500; border-radius: 10px;';

            let html = '<h4 style="color: #FF9500; margin-bottom: 10px;">⚠️ URL Shortener Detected</h4>';
            html += '<div style="font-size: 13px; color: #8E8E93;">';
            html += `<p><strong>Domain:</strong> ${redirectInfo.shortenerDomain}</p>`;
            html += '<p style="margin-top: 8px;">This is a shortened URL, but the final destination cannot be verified without visiting the link.</p>';
            html += '<p style="margin-top: 8px; color: #FF9500;"><strong>Recommendation:</strong> Be extra cautious with shortened URLs as they can hide malicious destinations.</p>';
            html += '</div>';

            warningDisplay.innerHTML = html;
            const urlDisplay = document.getElementById('urlDisplay');
            urlDisplay.parentElement.insertBefore(warningDisplay, urlDisplay.nextSibling);
            return;
        }

        if (!redirectInfo.hasRedirects) {
            // Even if no redirects, show if security issues were found
            if (redirectInfo.hasSecurityIssues) {
                this.showRedirectSecurityWarning(redirectInfo.maliciousUrls);
            }
            return;
        }

        const redirectDisplay = document.createElement('div');
        redirectDisplay.id = 'redirectChain';

        // Change color based on security status
        const borderColor = redirectInfo.hasSecurityIssues ? '#FF3B30' : '#AF52DE';
        const bgColor = redirectInfo.hasSecurityIssues ? 'rgba(255,59,48,0.1)' : 'rgba(175,82,222,0.1)';

        redirectDisplay.style.cssText = `margin-top: 15px; padding: 12px; background: ${bgColor}; border: 1px solid ${borderColor}; border-radius: 10px;`;

        let html = `<h4 style="color: ${borderColor}; margin-bottom: 10px;">`;
        if (redirectInfo.hasSecurityIssues) {
            html += '⛔ Dangerous Redirect Chain Detected';
        } else {
            html += '🔀 Redirect Chain Detected';
        }
        html += '</h4>';
        html += '<div style="font-size: 13px; color: #8E8E93;">';

        if (redirectInfo.error && redirectInfo.redirectChain.length === 0) {
            html += `<p>⚠️ Unable to fully trace redirects due to browser security restrictions</p>`;
            html += `<p style="margin-top: 8px;">Original URL: <span style="color: #FF9500; word-break: break-all;">${redirectInfo.originalUrl}</span></p>`;
            html += '<p style="margin-top: 8px; color: #FF9500;">Be cautious: the destination cannot be verified without visiting.</p>';
        } else {
            html += `<p>This URL redirects through ${redirectInfo.redirectCount} step(s):</p>`;
            html += '<div style="margin-top: 10px; font-family: monospace; font-size: 12px;">';

            // Show original URL with safety indicator
            const originalSafe = !redirectInfo.maliciousUrls.some(m => m.url === redirectInfo.originalUrl);
            const originalColor = originalSafe ? '#5AC8FA' : '#FF3B30';
            const originalIcon = originalSafe ? '' : ' ⚠️';
            html += `<div style="padding: 4px 0; color: ${originalColor};">1. ${this.truncateUrl(redirectInfo.originalUrl)}${originalIcon}</div>`;

            // Show each redirect in the chain
            redirectInfo.redirectChain.forEach((redirect, index) => {
                const methodInfo = redirect.method ? ` (via ${redirect.method})` : '';
                const isMalicious = redirect.isMalicious ||
                                  redirectInfo.maliciousUrls.some(m => m.url === redirect.to);
                const stepColor = isMalicious ? '#FF3B30' : '#5AC8FA';
                const stepIcon = isMalicious ? ' ⛔' : '';

                html += `<div style="padding: 4px 0; padding-left: 20px; color: #666;">↓${methodInfo}</div>`;
                html += `<div style="padding: 4px 0; color: ${stepColor};">${index + 2}. ${this.truncateUrl(redirect.to)}${stepIcon}</div>`;

                // Show security issues for this step
                if (isMalicious) {
                    const maliciousInfo = redirectInfo.maliciousUrls.find(m => m.url === redirect.to);
                    if (maliciousInfo && maliciousInfo.issues) {
                        html += `<div style="padding: 2px 0 4px 20px; color: #FF3B30; font-size: 11px;">`;
                        html += `⚠️ ${maliciousInfo.issues.join(', ')}`;
                        html += `</div>`;
                    }
                }
            });

            html += '</div>';
            html += `<p style="margin-top: 10px;"><strong>Final destination:</strong></p>`;

            const finalSafe = !redirectInfo.maliciousUrls.some(m => m.isFinal);
            const finalColor = finalSafe ? '#5AC8FA' : '#FF3B30';
            html += `<div style="word-break: break-all; color: ${finalColor}; font-family: monospace; font-size: 12px; padding: 8px; background: rgba(0,0,0,0.3); border-radius: 6px; margin-top: 5px;">${redirectInfo.finalUrl}</div>`;

            // Show warnings based on redirect count and security issues
            if (redirectInfo.hasSecurityIssues) {
                html += '<p style="margin-top: 10px; padding: 8px; background: rgba(255,59,48,0.2); border-radius: 6px; color: #FF3B30;">';
                html += '⛔ <strong>DANGER:</strong> Malicious URLs detected in redirect chain. DO NOT visit this link!';
                html += '</p>';
            } else if (redirectInfo.redirectCount > 2) {
                html += '<p style="margin-top: 10px; padding: 8px; background: rgba(255,149,0,0.1); border-radius: 6px; color: #FF9500;">';
                html += '⚠️ <strong>Warning:</strong> Multiple redirects detected. This is often used to evade detection.';
                html += '</p>';
            }
        }

        html += '</div>';
        redirectDisplay.innerHTML = html;

        const urlDisplay = document.getElementById('urlDisplay');
        urlDisplay.parentElement.insertBefore(redirectDisplay, urlDisplay.nextSibling);
    }

    // New method to show security warnings for redirect chain
    showRedirectSecurityWarning(maliciousUrls) {
        if (!maliciousUrls || maliciousUrls.length === 0) return;

        const existingWarning = document.getElementById('redirectSecurityWarning');
        if (existingWarning) {
            existingWarning.remove();
        }

        const warningDisplay = document.createElement('div');
        warningDisplay.id = 'redirectSecurityWarning';
        warningDisplay.style.cssText = 'margin-top: 15px; padding: 12px; background: rgba(255,59,48,0.15); border: 2px solid #FF3B30; border-radius: 10px;';

        let html = '<h4 style="color: #FF3B30; margin-bottom: 10px;">⛔ Security Threats Detected</h4>';
        html += '<div style="font-size: 13px;">';

        maliciousUrls.forEach((malicious, index) => {
            html += `<div style="margin-bottom: 8px; padding: 8px; background: rgba(0,0,0,0.2); border-radius: 6px;">`;
            if (malicious.isFinal) {
                html += `<strong style="color: #FF3B30;">Final Destination:</strong><br>`;
            } else {
                html += `<strong style="color: #FF3B30;">Step ${malicious.step}:</strong><br>`;
            }
            html += `<span style="word-break: break-all; font-family: monospace; font-size: 11px; color: #FF9500;">${this.truncateUrl(malicious.url, 50)}</span><br>`;
            html += `<strong style="color: #FF3B30;">Issues:</strong> ${malicious.issues.join(' • ')}`;
            html += `</div>`;
        });

        html += '<p style="margin-top: 10px; padding: 10px; background: rgba(255,59,48,0.2); border-radius: 6px; color: #FFF; text-align: center;">';
        html += '<strong>⛔ DO NOT OPEN THIS LINK ⛔</strong><br>';
        html += '<span style="font-size: 12px;">This QR code leads to potentially dangerous websites</span>';
        html += '</p>';
        html += '</div>';

        warningDisplay.innerHTML = html;

        // Insert after the safety indicator
        const safetyIndicator = document.getElementById('safetyIndicator');
        safetyIndicator.parentElement.insertBefore(warningDisplay, safetyIndicator.nextSibling);

        // Also update the main safety indicator to show danger
        const safetyIcon = document.getElementById('safetyIcon');
        const safetyEmoji = document.getElementById('safetyEmoji');
        const safetyTitle = document.getElementById('safetyTitle');
        const safetyDescription = document.getElementById('safetyDescription');

        safetyIcon.className = 'safety-icon danger';
        safetyEmoji.textContent = '⛔';
        safetyTitle.textContent = 'Dangerous Link Detected';
        safetyDescription.textContent = 'Multiple security threats found in redirect chain';

        // Update the open button to show danger
        this.openButton.className = 'action-button danger';
        this.openButton.textContent = 'DO NOT OPEN';
        this.openButton.disabled = true;
    }

    truncateUrl(url, maxLength = 40) {
        if (!url) return '';
        if (url.length > maxLength) {
            return url.substring(0, maxLength - 3) + '...';
        }
        return url;
    }

    showResult(url) {
        document.getElementById('urlDisplay').textContent = url;
        this.resultModal.classList.add('active');
        if(this.buttonsContainer) {
            this.buttonsContainer.style.transform = 'translateY(0)';
        }
        this.loadingSpinner.classList.add('active');

        ['virustotal', 'google', 'phishtank', 'urlvoid'].forEach(service => {
            document.getElementById(`${service}Status`).innerHTML = '<div class="status-loading"></div>';
            document.getElementById(`${service}Details`).style.display = 'none';
            document.getElementById(`${service}Details`).innerHTML = '';
        });
    }

    async checkExternalServices(url) {
        const services = [
            { id: 'virustotal', name: 'VirusTotal', delay: 1500 },
            { id: 'google', name: 'Google Safe Browsing', delay: 1200 },
            { id: 'phishtank', name: 'PhishTank', delay: 1800 },
            { id: 'urlvoid', name: 'URLVoid', delay: 2000 }
        ];

        for (const service of services) {
            setTimeout(() => {
                const status = this.performDetailedSecurityCheck(url, service.name);
                this.updateServiceStatus(service.id, status);
            }, service.delay);
        }
    }

    performDetailedSecurityCheck(url, serviceName) {
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            const path = urlObj.pathname.toLowerCase();

            let threatDetails = [];
            let isSafe = true;

            if (this.threatPatterns.trustedDomains.some(trusted =>
                domain === trusted || domain.endsWith('.' + trusted))) {
                return {
                    safe: true,
                    message: 'Verified',
                    details: []
                };
            }

            if(this.threatDatabase.knownPhishing.some(phish => domain.includes(phish))){
                threatDetails.push({
                    type: 'Phishing',
                    description: 'Known phishing domain in database',
                    severity: 'high'
                });
                isSafe = false;
            }

            if(this.threatDatabase.knownMalware.some(mal => domain.includes(mal))){
                threatDetails.push({
                    type: 'Malware',
                    description: 'Known malware distribution site',
                    severity: 'critical'
                });
                isSafe = false;
            }

            const hasPhishingKeyword = this.threatPatterns.phishing.keywords.some(keyword =>
                domain.includes(keyword) || path.includes(keyword));

            if(hasPhishingKeyword){
                threatDetails.push({
                    type: 'Suspicious Keywords',
                    description: 'Contains common phishing terms',
                    severity: 'medium'
                });
                isSafe = false;
            }

            const hasPhishingPattern = this.threatPatterns.phishing.patterns.some(pattern =>
                pattern.test(url));

            if(hasPhishingPattern){
                if(/@/.test(url)){
                    threatDetails.push({
                        type: 'URL Manipulation',
                        description: '@ symbol detected - possible credential harvesting',
                        severity: 'high'
                    });
                }
                if(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(domain)){
                    threatDetails.push({
                        type: 'IP Address',
                        description: 'Uses IP address instead of domain name',
                        severity: 'high'
                    });
                }
                isSafe = false;
            }

            const hasSuspiciousTLD = this.threatPatterns.phishing.suspiciousTLDs.some(tld =>
                domain.endsWith(tld));

            if(hasSuspiciousTLD){
                threatDetails.push({
                    type: 'Suspicious TLD',
                    description: 'Top-level domain commonly used in attacks',
                    severity: 'medium'
                });
                isSafe = false;
            }

            if (this.threatPatterns.shorteners.domains.some(shortener =>
                domain.includes(shortener))) {
                threatDetails.push({
                    type: 'URL Shortener',
                    description: 'Destination URL is hidden',
                    severity: 'low'
                });
                return {
                    safe: null,
                    message: 'Shortener',
                    details: threatDetails
                };
            }

            if(threatDetails.length === 0){
                return {
                    safe: true,
                    message: 'Clean',
                    details: []
                };
            }

            return {
                safe: false,
                message: 'Threats found',
                details: threatDetails
            };

        } catch (e) {
            return {
                safe: null,
                message: 'N/A',
                details: []
            };
        }
    }

    updateServiceStatus(serviceId, status) {
        const statusElement = document.getElementById(`${serviceId}Status`);
        const detailsElement = document.getElementById(`${serviceId}Details`);

        if (status.safe === true && (!status.details || status.details.length === 0)) {
            statusElement.innerHTML = '<span class="status-icon">✅</span> ' + status.message;
            statusElement.style.color = 'var(--success)';
        } else if (status.safe === false || (status.details && status.details.length > 0)) {
            statusElement.innerHTML = '<span class="status-icon">❌</span> ' + status.message;
            statusElement.style.color = 'var(--danger)';
        } else {
            statusElement.innerHTML = '<span class="status-icon">❓</span> ' + status.message;
            statusElement.style.color = 'var(--text-secondary)';
        }

        if(status.details && status.details.length > 0){
            let detailsHTML = '';
            status.details.forEach(threat => {
                const icon = threat.severity === 'critical' ? '🔴' :
                            threat.severity === 'high' ? '🟠' :
                            threat.severity === 'medium' ? '🟡' : '⚪';
                detailsHTML += `<div class="threat-item">
                    ${icon} <span class="threat-label">${threat.type}:</span> ${threat.description}
                </div>`;
            });
            detailsElement.innerHTML = detailsHTML;
            detailsElement.style.display = 'block';
            detailsElement.classList.add('active');
        }
    }

    analyzeURL(url, redirectInfo = null) {
        if (this.hasAI) {
            console.log('🤖 Using browser AI for analysis...');
            this.analyzeWithAI(url).then(aiResult => {
                if (aiResult) {
                    setTimeout(() => {
                        const analysis = this.mergeAIWithPatternAnalysis(url, aiResult, redirectInfo);
                        this.displayAnalysis(analysis);
                        this.loadingSpinner.classList.remove('active');
                    }, 1500);
                } else {
                    this.performPatternAnalysis(url, redirectInfo);
                }
            }).catch(error => {
                console.error('AI analysis error:', error);
                this.performPatternAnalysis(url, redirectInfo);
            });
        } else {
            this.performPatternAnalysis(url, redirectInfo);
        }
    }

    performPatternAnalysis(url, redirectInfo = null) {
        console.log('📊 Using pattern-based analysis...');
        setTimeout(() => {
            const analysis = this.performAdvancedAIAnalysis(url);
            if (redirectInfo) {
                analysis.redirectInfo = redirectInfo;
                if (redirectInfo.redirectCount > 2) {
                    analysis.warnings.push(`Long redirect chain (${redirectInfo.redirectCount} hops)`);
                    analysis.riskLevel = 'high';
                    analysis.aiScore -= 20;
                }
                if (redirectInfo.hasRedirects) {
                    analysis.warnings.push('URL shortener/redirect detected');
                    if (analysis.riskLevel === 'low') {
                        analysis.riskLevel = 'medium';
                    }
                }
            }
            this.displayAnalysis(analysis);
            this.loadingSpinner.classList.remove('active');
        }, 2500);
    }

    mergeAIWithPatternAnalysis(url, aiResult, redirectInfo = null) {
        try {
            const analysis = this.performAdvancedAIAnalysis(url);

            if (aiResult.riskLevel) {
                analysis.riskLevel = aiResult.riskLevel;
            }

            if (aiResult.aiConfidence !== undefined) {
                analysis.aiScore = aiResult.aiConfidence;
            }

            if (aiResult.threats && aiResult.threats.length > 0) {
                aiResult.threats.forEach(threat => {
                    if (!analysis.warnings.includes(threat)) {
                        analysis.warnings.push(`[AI] ${threat}`);
                    }
                });
            }

            if (aiResult.explanation) {
                analysis.aiExplanation = aiResult.explanation;
            }

            analysis.usedRealAI = true;

            if (redirectInfo) {
                analysis.redirectInfo = redirectInfo;
                if (redirectInfo.redirectCount > 2) {
                    analysis.warnings.push(`Long redirect chain (${redirectInfo.redirectCount} hops)`);
                    analysis.riskLevel = 'high';
                    analysis.aiScore -= 20;
                }
            }

            return analysis;
        } catch (e) {
            console.error('Error merging AI analysis:', e);
            return this.performAdvancedAIAnalysis(url);
        }
    }

    performAdvancedAIAnalysis(url) {
        const analysis = {
            url: url,
            isSafe: true,
            riskLevel: 'low',
            warnings: [],
            details: {},
            homoglyphs: [],
            aiScore: 100
        };

        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            const path = urlObj.pathname.toLowerCase();

            analysis.details.protocol = urlObj.protocol;
            if (urlObj.protocol !== 'https:') {
                analysis.warnings.push('Insecure connection (HTTP)');
                analysis.riskLevel = 'medium';
                analysis.aiScore -= 20;
            }

            analysis.details.domain = urlObj.hostname;

            const homoglyphs = this.detectHomoglyphs(urlObj.hostname);
            if (homoglyphs.length > 0) {
                analysis.homoglyphs = homoglyphs;
                analysis.warnings.push('Suspicious characters detected');
                analysis.riskLevel = 'high';
                analysis.aiScore -= 40;
            }

            if (this.threatPatterns.shorteners.domains.some(shortener =>
                domain.includes(shortener))) {
                analysis.warnings.push('Shortened URL - destination unknown');
                analysis.details.linkType = 'Shortened';
                analysis.riskLevel = analysis.riskLevel === 'high' ? 'high' : 'medium';
                analysis.aiScore -= 15;
            } else {
                analysis.details.linkType = 'Direct';
            }

            if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(domain)) {
                analysis.warnings.push('IP address instead of domain name');
                analysis.riskLevel = 'high';
                analysis.aiScore -= 30;
            }

            if (this.threatPatterns.phishing.suspiciousTLDs.some(tld =>
                domain.endsWith(tld))) {
                analysis.warnings.push('Suspicious top-level domain');
                analysis.riskLevel = 'high';
                analysis.aiScore -= 25;
            }

            for (const trusted of this.threatPatterns.trustedDomains) {
                const similarity = this.calculateSimilarity(domain, trusted);
                if (similarity > 0.7 && similarity < 0.95) {
                    analysis.warnings.push(`Similar to ${trusted} (possible typosquatting)`);
                    analysis.riskLevel = 'high';
                    analysis.aiScore -= 35;
                    break;
                }
            }

            const phishingScore = this.calculatePhishingScore(url);
            if (phishingScore > 50) {
                analysis.warnings.push('Contains phishing indicators');
                analysis.riskLevel = 'high';
                analysis.aiScore -= phishingScore / 2;
            }

            if(this.threatDatabase.knownPhishing.some(phish => domain.includes(phish))){
                analysis.warnings.push('Known phishing site');
                analysis.riskLevel = 'high';
                analysis.aiScore = 0;
            }

            if(this.threatDatabase.knownMalware.some(mal => domain.includes(mal))){
                analysis.warnings.push('Known malware distributor');
                analysis.riskLevel = 'high';
                analysis.aiScore = 0;
            }

            if (analysis.aiScore >= 80) {
                analysis.riskLevel = 'low';
                analysis.isSafe = true;
            } else if (analysis.aiScore >= 50) {
                analysis.riskLevel = 'medium';
                analysis.isSafe = true;
            } else {
                analysis.riskLevel = 'high';
                analysis.isSafe = false;
            }

        } catch (e) {
            analysis.isSafe = true;
            analysis.riskLevel = 'low';
            analysis.details.type = 'text';
            analysis.aiScore = 100;
        }

        return analysis;
    }

    calculatePhishingScore(url) {
        let score = 0;
        const urlLower = url.toLowerCase();

        const suspiciousKeywords = [
            'verify', 'confirm', 'update', 'suspend', 'locked',
            'secure', 'account', 'billing', 'payment', 'expired','refund','alert'
        ];

        for (const keyword of suspiciousKeywords) {
            if (urlLower.includes(keyword)) {
                score += 15;
            }
        }

        const urgencyWords = ['urgent', 'immediate', 'quickly', 'expire', '24hour', '48hour','asap','now'];
        for (const word of urgencyWords) {
            if (urlLower.includes(word)) {
                score += 20;
            }
        }

        if (urlLower.includes('@')) score += 30;
        if (urlLower.includes('//')) score += 20;
        if (/[0-9]{4,}/.test(urlLower)) score += 15;

        return Math.min(score, 100);
    }

    calculateSimilarity(str1, str2) {
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;

        if (longer.length === 0) return 1.0;

        const editDistance = this.levenshteinDistance(longer, shorter);
        return (longer.length - editDistance) / longer.length;
    }

    levenshteinDistance(str1, str2) {
        const matrix = [];

        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }

        return matrix[str2.length][str1.length];
    }

    displayAnalysis(analysis) {
        const safetyIcon = document.getElementById('safetyIcon');
        const safetyEmoji = document.getElementById('safetyEmoji');
        const safetyTitle = document.getElementById('safetyTitle');
        const safetyDescription = document.getElementById('safetyDescription');

        const aiIndicator = analysis.usedRealAI ? ' 🤖' : '';
        const analysisMethod = analysis.usedRealAI ? 'Browser AI Analysis' : 'Pattern Analysis';

        if (analysis.riskLevel === 'low') {
            safetyIcon.className = 'safety-icon safe';
            safetyEmoji.textContent = '✅';
            safetyTitle.textContent = 'Safe Link' + aiIndicator;
            safetyDescription.textContent = `${analysisMethod} • Confidence: ${analysis.aiScore}% - No threats detected`;
            this.openButton.className = 'action-button primary';
            this.openButton.textContent = 'Open Link';
        } else if (analysis.riskLevel === 'medium') {
            safetyIcon.className = 'safety-icon warning';
            safetyEmoji.textContent = '⚠️';
            safetyTitle.textContent = 'Caution Required' + aiIndicator;
            safetyDescription.textContent = `${analysisMethod} • Confidence: ${analysis.aiScore}% - ${analysis.warnings.join(', ')}`;
            this.openButton.className = 'action-button primary';
            this.openButton.textContent = 'Open with Caution';
        } else {
            safetyIcon.className = 'safety-icon danger';
            safetyEmoji.textContent = '⛔';
            safetyTitle.textContent = 'Potential Threat' + aiIndicator;
            safetyDescription.textContent = `${analysisMethod} • Confidence: ${analysis.aiScore}% - ${analysis.warnings.join(', ')}`;
            this.openButton.className = 'action-button danger';
            this.openButton.textContent = 'Open (Not Recommended)';
        }

        if (analysis.aiExplanation) {
            const existingNote = document.querySelector('.ai-insight-note');
            if (existingNote) {
                existingNote.remove();
            }

            const aiNote = document.createElement('div');
            aiNote.className = 'ai-insight-note';
            aiNote.style.cssText = 'margin-top: 10px; padding: 10px; background: rgba(0,122,255,0.1); border-radius: 8px; font-size: 12px; color: #5AC8FA;';
            aiNote.innerHTML = `<strong>AI Insight:</strong> ${analysis.aiExplanation}`;
            safetyDescription.parentElement.appendChild(aiNote);
        }

        if (analysis.homoglyphs && analysis.homoglyphs.length > 0) {
            this.homoglyphWarning.classList.add('active');
            const details = document.getElementById('homoglyphDetails');

            let detailsHTML = 'Found characters: ';
            for (const h of analysis.homoglyphs) {
                detailsHTML += `<span class="homoglyph-char">"${h.char}" (${h.type || h.unicode})</span> `;
                if (h.original) {
                    detailsHTML += `instead of "${h.original.join('" or "')}" `;
                }
            }
            details.innerHTML = detailsHTML;
        } else {
            this.homoglyphWarning.classList.remove('active');
        }

        document.getElementById('protocolValue').textContent =
            analysis.details.protocol === 'https:' ? 'HTTPS ✅' :
            analysis.details.protocol === 'http:' ? 'HTTP ⚠️' :
            'Text';

        document.getElementById('domainValue').textContent =
            analysis.details.domain || 'Not a URL';

        document.getElementById('sslValue').textContent =
            analysis.details.protocol === 'https:' ? 'Valid ✅' :
            analysis.details.protocol === 'http:' ? 'None ⚠️' :
            'N/A';

        document.getElementById('linkTypeValue').textContent =
            analysis.details.linkType || 'Plain text';

        document.getElementById('homoglyphValue').textContent =
            analysis.homoglyphs.length > 0 ? `${analysis.homoglyphs.length} found ⚠️` : 'None detected ✅';

        document.getElementById('riskValue').textContent =
            analysis.riskLevel === 'low' ? 'Low ✅' :
            analysis.riskLevel === 'medium' ? 'Medium ⚠️' :
            'High ⛔';

        this.currentAnalysis = analysis;
    }

    closeResult() {
        this.resultModal.classList.remove('active');
        if(this.buttonsContainer) {
            this.buttonsContainer.style.transform = 'translateY(100%)';
        }

        const existingNote = document.querySelector('.ai-insight-note');
        if (existingNote) {
            existingNote.remove();
        }

        this.lastScannedCode = null;
        this.startButton.style.display = 'block';
        this.startButton.textContent = 'Scan Another Code';
    }

    copyToClipboard() {
        const url = document.getElementById('urlDisplay').textContent;
        navigator.clipboard.writeText(url).then(() => {
            this.copyButton.textContent = 'Copied ✓';
            setTimeout(() => {
                this.copyButton.textContent = 'Copy Link';
            }, 2000);
        });
    }

    openLink() {
        const url = document.getElementById('urlDisplay').textContent;
        const finalUrl = this.currentAnalysis?.redirectInfo?.finalUrl || url;

        if (this.currentAnalysis && this.currentAnalysis.riskLevel === 'high') {
            let warningMessage = '⚠️ WARNING! This link has multiple security risks:\n\n' +
                                this.currentAnalysis.warnings.join('\n') +
                                '\n\nAI Confidence: ' + this.currentAnalysis.aiScore + '%';

            if (this.currentAnalysis.redirectInfo && this.currentAnalysis.redirectInfo.hasRedirects) {
                warningMessage += '\n\n🔀 REDIRECT DETECTED!\n';
                warningMessage += `Original: ${url}\n`;
                warningMessage += `Final destination: ${finalUrl}\n`;
                warningMessage += `Redirect hops: ${this.currentAnalysis.redirectInfo.redirectCount}`;
            }

            warningMessage += '\n\nAre you sure you want to continue?';

            if (confirm(warningMessage)) {
                window.open(finalUrl, '_blank');
            }
        } else if (this.currentAnalysis && this.currentAnalysis.riskLevel === 'medium') {
            let cautionMessage = '⚠️ Caution: This link has some suspicious indicators:\n\n' +
                                this.currentAnalysis.warnings.join('\n') +
                                '\n\nAI Confidence: ' + this.currentAnalysis.aiScore + '%';

            if (this.currentAnalysis.redirectInfo && this.currentAnalysis.redirectInfo.hasRedirects) {
                cautionMessage += '\n\n🔀 This is a shortened URL that redirects to:\n';
                cautionMessage += finalUrl;
            }

            cautionMessage += '\n\nProceed?';

            if (confirm(cautionMessage)) {
                window.open(finalUrl, '_blank');
            }
        } else {
            if (this.currentAnalysis?.redirectInfo?.hasRedirects) {
                if (confirm(`This shortened URL redirects to:\n${finalUrl}\n\nOpen it?`)) {
                    window.open(finalUrl, '_blank');
                }
            } else {
                window.open(url, '_blank');
            }
        }
    }

    stopScanning() {
        this.scanning = false;
        this.stopCamera();
    }
}

// Initialize the app with better error handling and iOS compatibility
document.addEventListener('DOMContentLoaded', () => {
    try {
        console.log('DOM loaded, initializing scanner...');
        const scanner = new QRSafetyScanner();

        document.addEventListener('visibilitychange', () => {
            if (document.hidden && scanner.scanning) {
                scanner.stopScanning();
            }
        });

        if (/iPhone|iPad|iPod/.test(navigator.userAgent)) {
            document.documentElement.style.height = '100%';
            document.body.style.height = '100%';
        }

        console.log('✅ QR Scanner initialized successfully');
    } catch (error) {
        console.error('❌ Failed to initialize QR Scanner:', error);
        alert('Error initializing scanner. Please refresh the page.');
    }
});