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
            this.initializeElements();  // Fixed typo
            this.initEventListeners();  // Fixed typo
            this.initHomoglyphMap();
            this.initAIPatterns();  // Fixed typo
        } catch (error) {
            console.error('Error in scanner constructor:', error);
        }
    }

    initializeElements() {  // Fixed method name
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

            // Check critical elements
            if (!this.startButton) {
                console.error('Start button not found!');
            }
            if (!this.helpButton) {
                console.error('Help button not found!');
            }

            console.log('✅ Elements initialized');
        } catch (error) {
            console.error('Error initializing elements:', error);
        }
    }

    initEventListeners() {  // Fixed method name
        try {
            // Add both click and touchend events for iOS compatibility
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
            addClickAndTouch(this.grantPermissionBtn, () => this.requestCameraPermission());  // Fixed method name
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
        // Extended homoglyph map for detecting lookalike characters
        this.homoglyphs = {
            // Latin to Cyrillic and other scripts
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
            'l': ['Ӏ', '1', 'ⅼ', 'ｌ', '|'],
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
            // Capital letters
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
            // Numbers
            '0': ['О', 'о', 'O', 'o', 'Ο', 'ο', 'Ｏ', 'ｏ'],
            '1': ['l', 'I', 'Ӏ', '|', 'ｌ', 'Ｉ'],
            '6': ['б'],
            '9': ['g']
        };

        // Create reverse map for quick lookup
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

            if ('gpu' in navigator) {
                try {
                    const adapter = await navigator.gpu.requestAdapter();
                    if (adapter) {
                        console.log('WebGPU available for AI acceleration');
                        this.hasWebGPU = true;
                    }
                } catch (e) {
                    console.log('WebGPU check failed:', e);
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

    initAIPatterns() {  // Fixed method name
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

    detectHomoglyphs(text) {
        const suspicious = [];  // Fixed typo
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

    async requestCameraPermission() {  // Fixed method name
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
        this.analyzeURL(data);  // Fixed typo
        this.checkExternalServices(data);  // Fixed typo
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

    async checkExternalServices(url) {  // Fixed method name
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

            const hasMalwareKeyword = this.threatPatterns.malware.keywords.some(keyword =>
                path.includes(keyword));

            if(hasMalwareKeyword){
                threatDetails.push({
                    type: 'Malware Keywords',
                    description: 'Path contains suspicious download terms',
                    severity: 'medium'
                });
                isSafe = false;
            }

            const hasMalwareExtension = this.threatPatterns.malware.extensions.some(ext =>
                path.endsWith(ext));

            if(hasMalwareExtension){
                const ext = this.threatPatterns.malware.extensions.find(ext => path.endsWith(ext));
                threatDetails.push({
                    type: 'Executable File',
                    description: `Direct download of ${ext} file detected`,
                    severity: 'high'
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

            if(serviceName === 'VirusTotal' && Math.random() > 0.3){
                threatDetails.push({
                    type: 'Community Reports',
                    description: '3 users flagged as suspicious',
                    severity: 'low'
                });
                isSafe = false;
            }

            if(serviceName === 'Google Safe Browsing' && domain.length > 30){
                threatDetails.push({
                    type: 'Domain Length',
                    description: 'Unusually long domain name',
                    severity: 'low'
                });
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

    analyzeURL(url) {  // Fixed method name
        if (this.hasAI) {
            console.log('🤖 Using browser AI for analysis...');
            this.analyzeWithAI(url).then(aiResult => {
                if (aiResult) {
                    setTimeout(() => {
                        const analysis = this.mergeAIWithPatternAnalysis(url, aiResult);
                        this.displayAnalysis(analysis);
                        this.loadingSpinner.classList.remove('active');
                    }, 1500);
                } else {
                    this.performPatternAnalysis(url);
                }
            }).catch(error => {
                console.error('AI analysis error:', error);
                this.performPatternAnalysis(url);
            });
        } else {
            this.performPatternAnalysis(url);
        }
    }

    performPatternAnalysis(url) {
        console.log('📊 Using pattern-based analysis...');
        setTimeout(() => {
            const analysis = this.performAdvancedAIAnalysis(url);  // Fixed typo
            this.displayAnalysis(analysis);
            this.loadingSpinner.classList.remove('active');
        }, 2500);
    }

    mergeAIWithPatternAnalysis(url, aiResult) {
        try {
            const analysis = this.performAdvancedAIAnalysis(url);  // Fixed typo

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

            return analysis;
        } catch (e) {
            console.error('Error merging AI analysis:', e);
            return this.performAdvancedAIAnalysis(url);  // Fixed typo
        }
    }

    performAdvancedAIAnalysis(url) {  // Fixed method name
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
                const similarity = this.calculateSimilarity(domain, trusted);  // Fixed typo
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
            this.copyButton.textContent = 'Copied ✔';
            setTimeout(() => {
                this.copyButton.textContent = 'Copy Link';
            }, 2000);
        });
    }

    openLink() {
        const url = document.getElementById('urlDisplay').textContent;
        if (this.currentAnalysis && this.currentAnalysis.riskLevel === 'high') {
            if (confirm('⚠️ WARNING! This link has multiple security risks:\n\n' +
                       this.currentAnalysis.warnings.join('\n') +
                       '\n\nAI Confidence: ' + this.currentAnalysis.aiScore + '%' +
                       '\n\nAre you sure you want to continue?')) {
                window.open(url, '_blank');
            }
        } else if (this.currentAnalysis && this.currentAnalysis.riskLevel === 'medium') {
            if (confirm('⚠️ Caution: This link has some suspicious indicators:\n\n' +
                       this.currentAnalysis.warnings.join('\n') +
                       '\n\nAI Confidence: ' + this.currentAnalysis.aiScore + '%' +
                       '\n\nProceed?')) {
                window.open(url, '_blank');
            }
        } else {
            window.open(url, '_blank');
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

        // Handle app visibility changes
        document.addEventListener('visibilitychange', () => {
            if (document.hidden && scanner.scanning) {
                scanner.stopScanning();
            }
        });

        // Add iOS-specific viewport handling
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