/* ==============================================================================
   CVE THREAT INTEL DASHBOARD - INTERACTIVE APPLICATION CONTROLLER
   ============================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    
    // Global Elements
    const elements = {
        tabs: document.querySelectorAll(".nav-item"),
        panels: document.querySelectorAll(".tab-panel"),
        tabHeading: document.getElementById("tab-heading"),
        tabSubheading: document.getElementById("tab-subheading"),
        liveTime: document.getElementById("live-time"),
        quickRefreshBtn: document.getElementById("quick-refresh-btn"),
        
        // KPI Widget Numbers
        kpiTotal: document.getElementById("kpi-total-cves"),
        kpiCritical: document.getElementById("kpi-critical-cves"),
        kpiAvgCvss: document.getElementById("kpi-avg-cvss"),
        kpiThreat: document.getElementById("kpi-active-threat"),
        
        // Search & Scan
        searchVal: document.getElementById("cve-search-input"),
        searchBtn: document.getElementById("cve-submit-btn"),
        reportCard: document.getElementById("cve-report-card"),
        placeholderCard: document.getElementById("cve-placeholder-card"),
        searchError: document.getElementById("lookup-error-message"),
        searchSuccess: document.getElementById("lookup-success-message"),
        exampleBtns: document.querySelectorAll(".badge-example"),
        
        // Explorer Database
        explorerSearch: document.getElementById("explorer-search"),
        filterSeverity: document.getElementById("filter-severity"),
        filterExploit: document.getElementById("filter-exploit"),
        explorerTable: document.getElementById("cve-explorer-table").querySelector("tbody"),
        explorerInfo: document.getElementById("explorer-info-text"),
        explorerPrev: document.getElementById("explorer-prev-btn"),
        explorerNext: document.getElementById("explorer-next-btn"),
        exportCsv: document.getElementById("export-csv-btn"),
        
        // Markov threat panels
        hmmCurrentState: document.getElementById("hmm-current-state"),
        hmmLastCvss: document.getElementById("hmm-last-cvss"),
        hmmPredictedState: document.getElementById("hmm-predicted-state"),
        hmmProbability: document.getElementById("hmm-probability"),
        hmmExpectedCvss: document.getElementById("hmm-expected-cvss"),
        meanLow: document.getElementById("mean-low"),
        meanMed: document.getElementById("mean-med"),
        meanHigh: document.getElementById("mean-high"),
        
        // MEMM Slider
        memmSlider: document.getElementById("memm-cvss-slider"),
        memmValText: document.getElementById("memm-cvss-val"),
        memmPredictedLabel: document.getElementById("memm-predicted-label"),
        fillLow: document.getElementById("fill-low"),
        fillMed: document.getElementById("fill-med"),
        fillHigh: document.getElementById("fill-high"),
        pctLow: document.getElementById("pct-low"),
        pctMed: document.getElementById("pct-med"),
        pctHigh: document.getElementById("pct-high"),
        
        // Training & Settings
        btnTrain: document.getElementById("btn-retrain-models"),
        trainStatusText: document.getElementById("last-train-status"),
        scoreMae: document.getElementById("model-score-mae"),
        scoreRmse: document.getElementById("model-score-rmse"),
        scoreMemm: document.getElementById("model-score-memm"),
        btnTrainRf: document.getElementById("btn-train-rf"),
        btnTrainHmm: document.getElementById("btn-train-hmm"),
        btnTrainMemm: document.getElementById("btn-train-memm"),
        btnTrainBert: document.getElementById("btn-train-bert"),
        statusRf: document.getElementById("status-rf"),
        statusHmm: document.getElementById("status-hmm"),
        statusMemm: document.getElementById("status-memm"),
        statusBert: document.getElementById("status-bert"),
        anthropicKey: document.getElementById("api-key-anthropic"),
        openaiKey: document.getElementById("api-key-openai"),
        btnSaveKeys: document.getElementById("btn-save-keys"),
        btnResetDb: document.getElementById("btn-reset-database"),
        resetSuccess: document.getElementById("reset-success-message"),
        forecastTable: document.getElementById("forecast-table").querySelector("tbody"),
    };

    // Subheadings per Tab
    const tabDetails = {
        overview: {
            title: "Vulnerability Center",
            subtitle: "Live threat scanning, rule-based NER extraction, and CVSS score regression"
        },
        analytics: {
            title: "Trend Analytics",
            subtitle: "Historical data distributions, exploit vector breakdowns, and asset clusters"
        },
        forecasting: {
            title: "Time-Series Forecast",
            subtitle: "Predicting future vulnerability volume trends using ARIMA and linear regressions"
        },
        "hmm-memm": {
            title: "Markov Threat Sequences",
            subtitle: "Hidden Markov (HMM) sequence decoders and discriminative transition probability modeling"
        },
        explorer: {
            title: "SQLite Vulnerability Vault",
            subtitle: "Browse, filter, and export the entire repository of analyzed vulnerabilities"
        },
        models: {
            title: "Model Engine Config",
            subtitle: "Re-train machine learning boundaries, configure LLM credentials, and database resets"
        }
    };

    // Global Chart.js Instances (caching to allow destroy on re-draw)
    const charts = {
        exploits: null,
        components: null,
        cvssDist: null,
        forecast: null,
        hmmSequence: null
    };

    // DB Pagination State
    let dbOffset = 0;
    const dbLimit = 25;
    let dbTotal = 0;

    // API Key Local Storage keys
    const KEYS = {
        anthropic: "threat_intel_anthropic_key",
        openai: "threat_intel_openai_key"
    };

    // Initialize Credentials
    if (localStorage.getItem(KEYS.anthropic)) elements.anthropicKey.value = localStorage.getItem(KEYS.anthropic);
    if (localStorage.getItem(KEYS.openai)) elements.openaiKey.value = localStorage.getItem(KEYS.openai);

    // ==============================================================================
    // 1. GENERAL UTILITIES (Clock, Active States)
    // ==============================================================================
    
    // Live clock update
    const updateTime = () => {
        const now = new Date();
        elements.liveTime.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    };
    setInterval(updateTime, 1000);
    updateTime();

    // Tab Navigation Logic
    elements.tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const target = tab.getAttribute("data-tab");
            
            // Toggle sidebar button selection
            elements.tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            // Toggle active content board
            elements.panels.forEach(panel => panel.classList.remove("active"));
            const targetPanel = document.getElementById(`panel-${target}`);
            if (targetPanel) targetPanel.classList.add("active");

            // Update title text
            if (tabDetails[target]) {
                elements.tabHeading.textContent = tabDetails[target].title;
                elements.tabSubheading.textContent = tabDetails[target].subtitle;
            }

            // Trigger specific chart load or table updates on tab switch
            if (target === "analytics") loadAnalyticsCharts();
            if (target === "forecasting") loadForecastCharts();
            if (target === "hmm-memm") {
                loadMarkovSequenceChart();
                updateMEMMSimulator();
            }
            if (target === "explorer") loadExplorerData();
        });
    });

    // Helper: Severity color mapping matching HSL layout
    const getSeverityPillClass = (sev) => {
        sev = (sev || "").toUpperCase();
        if (sev === "CRITICAL") return "pill-critical";
        if (sev === "HIGH") return "pill-high";
        if (sev === "MEDIUM") return "pill-medium";
        if (sev === "LOW") return "pill-low";
        return "pill-unknown";
    };

    // ==============================================================================
    // 2. NETWORK DATA RETRIEVAL (API BINDINGS)
    // ==============================================================================

    // General application status & KPI widget updates
    const fetchSystemStatus = async () => {
        try {
            const res = await fetch("/api/status");
            if (!res.ok) throw new Error("API Offline");
            
            const data = await res.json();
            
            // Set KPI texts
            elements.kpiTotal.textContent = data.cve_count.toLocaleString();
            
            const highCritCount = (data.severities.HIGH || 0) + (data.severities.CRITICAL || 0);
            elements.kpiCritical.textContent = highCritCount.toLocaleString();
            
            elements.kpiAvgCvss.textContent = data.avg_cvss.toFixed(1);
            
            // Update models metrics page numbers
            elements.scoreMae.textContent = data.rf_mae > 0 ? data.rf_mae.toFixed(3) : "-";
            elements.scoreRmse.textContent = data.rf_rmse > 0 ? data.rf_rmse.toFixed(3) : "-";
            elements.scoreMemm.textContent = data.memm_accuracy > 0 ? `${data.memm_accuracy.toFixed(1)}%` : "-";
            
            document.getElementById("server-status-text").textContent = "Server: Connected";
            document.querySelector(".pulse-dot").className = "pulse-dot green";
            
            // Load HMM prediction for the KPI widget
            fetchHMDKPIWidget();
        } catch (err) {
            document.getElementById("server-status-text").textContent = "Server: Offline";
            document.querySelector(".pulse-dot").className = "pulse-dot red";
            console.error("Failed to connect to backend uvicorn:", err);
        }
    };

    // Separate widget fetch for Markov active state
    const fetchHMDKPIWidget = async () => {
        try {
            const res = await fetch("/api/analysis/hmm");
            if (!res.ok) return;
            const data = await res.json();
            elements.kpiThreat.textContent = data.predicted_next_state.replace(" Threat", "");
        } catch (err) {
            elements.kpiThreat.textContent = "N/A";
        }
    };

    // Execute first KPI fetch on DOM load
    fetchSystemStatus();

    // Refresh Action
    elements.quickRefreshBtn.addEventListener("click", () => {
        fetchSystemStatus();
        
        // Refresh whatever is currently open
        const activeTab = document.querySelector(".nav-item.active").getAttribute("data-tab");
        if (activeTab === "analytics") loadAnalyticsCharts();
        if (activeTab === "forecasting") loadForecastCharts();
        if (activeTab === "hmm-memm") {
            loadMarkovSequenceChart();
            updateMEMMSimulator();
        }
        if (activeTab === "explorer") loadExplorerData();
    });

    // ==============================================================================
    // 3. OVERVIEW: SEARCH AND SCAN ENGINE
    // ==============================================================================

    // Performs live search/NVD API lookup
    const executeCVELookup = async (cveId) => {
        if (!cveId) return;
        
        // Reset logs
        elements.searchError.classList.add("hidden");
        elements.searchSuccess.classList.add("hidden");
        elements.searchBtn.disabled = true;
        elements.searchBtn.querySelector("span").textContent = "Scanning NVD...";
        
        try {
            const res = await fetch(`/api/cve/lookup?cve_id=${encodeURIComponent(cveId)}`);
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || "Lookup failed.");
            }
            
            const data = await res.json();
            
            // Switch layout cards
            elements.placeholderCard.classList.add("hidden");
            elements.reportCard.classList.remove("hidden");
            
            // Format score and confidence width percentages
            const barScorePercent = Math.min(100, (data.CVSS_Score / 10) * 100);
            const barConfPercent = Math.min(100, data.Severity_Confidence * 100);
            
            const sourceBadge = data.source === "nvd_api_live" ? "NVD API v2.0 (Live)" : "Local SQL Storage";
            
            // Render Report Card Template
            elements.reportCard.innerHTML = `
                <div class="report-header-sec">
                    <div class="report-header-left">
                        <span>${data.CVE_ID} · Published ${data.Year} · Source: ${sourceBadge}</span>
                        <h2>${data.CVE_ID}</h2>
                        <div class="severity-pill-glow ${getSeverityPillClass(data.True_Severity)}">${data.True_Severity} SEVERITY</div>
                    </div>
                    <div class="report-header-right">
                        <div class="score-box-label">CVSS Base Score</div>
                        <div class="score-box-val">${data.CVSS_Score.toFixed(1)}</div>
                    </div>
                </div>

                <div class="report-section">
                    <div class="bar-metrics-grid">
                        <div class="metric-bar-item">
                            <span class="label">True Severity</span>
                            <div class="progress-track">
                                <div class="progress-fill red" style="width: ${barScorePercent}%"></div>
                            </div>
                            <span class="val">${data.CVSS_Score.toFixed(1)}</span>
                        </div>
                        <div class="metric-bar-item">
                            <span class="label">ML Prediction</span>
                            <div class="progress-track">
                                <div class="progress-fill blue" style="width: ${barConfPercent}%"></div>
                            </div>
                            <span class="val">${(data.Severity_Confidence * 100).toFixed(0)}%</span>
                        </div>
                    </div>
                </div>

                <div class="report-asset-grid">
                    <div class="asset-tile">
                        <span class="asset-tile-label">CWE Weakness</span>
                        <div class="asset-tile-val">${data.CWE}</div>
                    </div>
                    <div class="asset-tile">
                        <span class="asset-tile-label">Asset Component</span>
                        <div class="asset-tile-val">${data.Affected_Component}</div>
                    </div>
                    <div class="asset-tile">
                        <span class="asset-tile-label">Exploit Vector</span>
                        <div class="asset-tile-val">${data.Exploit_Type}</div>
                    </div>
                </div>

                <div class="report-section no-border">
                    <div class="report-text-block">
                        <h4>Impact Parameters</h4>
                        <p>${data.Impact}</p>
                    </div>
                    <div class="report-text-block glowing-bg">
                        <h4>NLP Preprocessing logs</h4>
                        <p class="font-mono" style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--accent-blue);">
                            &gt; raw: "${data.Description.substring(0, 120)}..."<br>
                            &gt; cleaned: "${data.Cleaned_Description.substring(0, 120)}..."
                        </p>
                    </div>
                    <div class="report-text-block">
                        <h4>NVD Description Summary</h4>
                        <p>${data.Description}</p>
                    </div>
                </div>
            `;
            
            elements.searchSuccess.classList.remove("hidden");
            elements.searchSuccess.textContent = `Vulnerability ${data.CVE_ID} loaded successfully from ${data.source === 'nvd_api_live' ? 'NVD' : 'cache'}.`;
            
            // Re-fetch totals
            fetchSystemStatus();
        } catch (err) {
            elements.searchError.classList.remove("hidden");
            elements.searchError.textContent = `Scan Failed: ${err.message}`;
            elements.placeholderCard.classList.remove("hidden");
            elements.reportCard.classList.add("hidden");
        } finally {
            elements.searchBtn.disabled = false;
            elements.searchBtn.querySelector("span").textContent = "Analyze";
        }
    };

    // Bind Search Trigger
    elements.searchBtn.addEventListener("click", () => {
        executeCVELookup(elements.searchVal.value);
    });

    // Support keyboard Enter key
    elements.searchVal.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            executeCVELookup(elements.searchVal.value);
        }
    });

    // Support quick examples clicks
    elements.exampleBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetCve = btn.getAttribute("data-cve");
            elements.searchVal.value = targetCve;
            executeCVELookup(targetCve);
        });
    });

    // ==============================================================================
    // 4. TAB: TREND ANALYTICS CHARTS (BAR, DOUGHNUT, DENSITY)
    // ==============================================================================

    const loadAnalyticsCharts = async () => {
        try {
            const res = await fetch("/api/status");
            if (!res.ok) return;
            const data = await res.json();

            // Fetch detail status stats
            const resDetail = await fetch("/api/status");
            const dbStats = await resDetail.json(); // Re-read to guarantee sync
            
            // --- 1. Exploit Type Bar Chart ---
            const exploitLabels = Object.keys(dbStats.exploits);
            const exploitCounts = Object.values(dbStats.exploits);
            
            if (charts.exploits) charts.exploits.destroy();
            
            const ctxExploits = document.getElementById("chart-exploits").getContext("2d");
            charts.exploits = new Chart(ctxExploits, {
                type: 'bar',
                data: {
                    labels: exploitLabels,
                    datasets: [{
                        label: 'Exploit Vector Count',
                        data: exploitCounts,
                        backgroundColor: 'rgba(0, 242, 254, 0.45)',
                        borderColor: '#00f2fe',
                        borderWidth: 1.5,
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: { backgroundColor: '#0e1322', titleColor: '#00f2fe', borderColor: 'rgba(0,242,254,0.2)', borderWidth: 1 }
                    },
                    scales: {
                        y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8' } },
                        x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                    }
                }
            });

            // --- 2. Affected Component Doughnut Chart ---
            const compLabels = Object.keys(dbStats.components);
            const compCounts = Object.values(dbStats.components);

            if (charts.components) charts.components.destroy();
            const ctxComponents = document.getElementById("chart-components").getContext("2d");
            charts.components = new Chart(ctxComponents, {
                type: 'doughnut',
                data: {
                    labels: compLabels,
                    datasets: [{
                        data: compCounts,
                        backgroundColor: [
                            '#ff3e6c', '#00f2fe', '#05d5a1', '#f5b041', '#a569bd',
                            '#3498db', '#1abc9c', '#e67e22', '#9b59b6', '#34495e'
                        ],
                        borderWidth: 1.5,
                        borderColor: '#090d16'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Outfit', size: 11 } } },
                        tooltip: { backgroundColor: '#0e1322' }
                    },
                    cutout: '65%'
                }
            });

            // --- 3. CVSS Score Distribution Frequency Chart ---
            // Let's call /api/cves to fetch all scores
            const resCves = await fetch("/api/cves?limit=1000");
            const cvesData = await resCves.json();
            
            // Build score density bins
            const bins = Array(10).fill(0);
            cvesData.cves.forEach(c => {
                const idx = Math.floor(Math.min(9.9, c.CVSS_Score));
                bins[idx]++;
            });

            if (charts.cvssDist) charts.cvssDist.destroy();
            const ctxCvss = document.getElementById("chart-cvss-dist").getContext("2d");
            
            // Glowing Area chart
            const grad = ctxCvss.createLinearGradient(0, 0, 0, 300);
            grad.addColorStop(0, 'rgba(165, 105, 189, 0.45)');
            grad.addColorStop(1, 'rgba(165, 105, 189, 0.0)');

            charts.cvssDist = new Chart(ctxCvss, {
                type: 'line',
                data: {
                    labels: ['0-1', '1-2', '2-3', '3-4', '4-5', '5-6', '6-7', '7-8', '8-9', '9-10'],
                    datasets: [{
                        label: 'Vulnerability Density',
                        data: bins,
                        fill: true,
                        backgroundColor: grad,
                        borderColor: '#a569bd',
                        borderWidth: 2,
                        tension: 0.4,
                        pointBackgroundColor: '#a569bd'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: { backgroundColor: '#0e1322' }
                    },
                    scales: {
                        y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8' } },
                        x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8' } }
                    }
                }
            });

        } catch (err) {
            console.error("Failed to build analytics visualizers:", err);
        }
    };

    // ==============================================================================
    // 5. TAB: FORECASTING CHARTS (ARIMA + REGRESSION LINE)
    // ==============================================================================

    const loadForecastCharts = async () => {
        try {
            const res = await fetch("/api/analysis/forecast");
            if (!res.ok) return;
            const data = await res.json();

            // Populate table details
            elements.forecastTable.innerHTML = "";
            
            // Loop history first
            data.history.forEach(row => {
                elements.forecastTable.innerHTML += `
                    <tr>
                        <td class="font-mono font-bold">${row.year}</td>
                        <td class="font-mono text-center font-bold text-primary">${row.actual}</td>
                        <td class="text-muted text-center">-</td>
                        <td class="font-mono text-center text-muted">${row.linear_trend.toFixed(1)}</td>
                    </tr>
                `;
            });

            // Loop forecasts next
            data.forecast.forEach(row => {
                elements.forecastTable.innerHTML += `
                    <tr style="background: rgba(5, 213, 161, 0.03);">
                        <td class="font-mono text-green font-bold">${row.year} <span style="font-size:9px; font-weight:700; color:var(--accent-green);">(FC)</span></td>
                        <td class="text-muted text-center">-</td>
                        <td class="font-mono text-center text-green font-bold" style="color: var(--accent-green);">${row.arima_prediction.toFixed(1)}</td>
                        <td class="font-mono text-center text-muted">${row.linear_prediction.toFixed(1)}</td>
                    </tr>
                `;
            });

            // Compile chart labels
            const histYears = data.history.map(h => h.year);
            const fcYears = data.forecast.map(f => f.year);
            const allYears = [...histYears, ...fcYears];

            const actualCounts = [...data.history.map(h => h.actual), ...Array(fcYears.length).fill(null)];
            
            const linearTrend = [
                ...data.history.map(h => h.linear_trend),
                ...data.forecast.map(f => f.linear_prediction)
            ];

            const arimaTrend = [
                ...Array(histYears.length - 1).fill(null),
                data.history[data.history.length - 1].actual, // bridge point
                ...data.forecast.map(f => f.arima_prediction)
            ];

            // Render ARIMA count line plot
            if (charts.forecast) charts.forecast.destroy();
            const ctxForecast = document.getElementById("chart-forecast").getContext("2d");
            charts.forecast = new Chart(ctxForecast, {
                type: 'line',
                data: {
                    labels: allYears,
                    datasets: [
                        {
                            label: 'Historical Actual',
                            data: actualCounts,
                            borderColor: '#00f2fe',
                            borderWidth: 2.5,
                            pointBackgroundColor: '#00f2fe',
                            tension: 0.25
                        },
                        {
                            label: 'ARIMA Forecast',
                            data: arimaTrend,
                            borderColor: '#05d5a1',
                            borderWidth: 2.5,
                            borderDash: [5, 5],
                            pointBackgroundColor: '#05d5a1',
                            tension: 0.25
                        },
                        {
                            label: 'Linear Trend-Line',
                            data: linearTrend,
                            borderColor: '#ff3e6c',
                            borderWidth: 1.5,
                            borderDash: [2, 2],
                            pointStyle: 'none',
                            pointBackgroundColor: 'transparent',
                            tension: 0
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top', labels: { color: '#94a3b8' } },
                        tooltip: { backgroundColor: '#0e1322' }
                    },
                    scales: {
                        y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8' } },
                        x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8' } }
                    }
                }
            });

        } catch (err) {
            console.error("Failed to calculate time series ARIMA models:", err);
        }
    };

    // ==============================================================================
    // 6. TAB: MARKOV SEQUENCES & TRANSITION HEATMAPS
    // ==============================================================================

    const loadMarkovSequenceChart = async () => {
        try {
            const res = await fetch("/api/analysis/hmm");
            if (!res.ok) return;
            const data = await res.json();

            // Populate forecast card widgets
            elements.hmmCurrentState.textContent = data.current_state.toUpperCase();
            elements.hmmLastCvss.textContent = `Last Observed CVSS: ${data.last_cvss.toFixed(1)}`;
            elements.hmmPredictedState.textContent = data.predicted_next_state.toUpperCase();
            elements.hmmProbability.textContent = `Transition Probability: ${(data.probability * 100).toFixed(1)}%`;
            elements.hmmExpectedCvss.textContent = `Expected Next CVSS: ${data.expected_next_cvss.toFixed(2)}`;

            // Populate state means
            elements.meanLow.textContent = data.means[0].toFixed(2);
            elements.meanMed.textContent = data.means[1].toFixed(2);
            elements.meanHigh.textContent = data.means[2].toFixed(2);

            // Set matrix transition probabilities in grid
            const mat = data.transition_matrix;
            for (let i = 0; i < 3; i++) {
                for (let j = 0; j < 3; j++) {
                    const cell = document.getElementById(`t-${i}-${j}`);
                    if (cell) {
                        const val = mat[i][j];
                        cell.textContent = val.toFixed(3);
                        // Shade backing based on intensity
                        cell.style.background = `rgba(0, 242, 254, ${val * 0.4})`;
                    }
                }
            }

            // Scatter Plot for chronological states
            const colors = { "Low Threat": "#3b82f6", "Medium Threat": "#10b981", "High Threat": "#ef4444" };
            
            const lowPoints = [];
            const medPoints = [];
            const highPoints = [];
            
            data.timeline.forEach((pt, index) => {
                const point = { x: index, y: pt.cvss, cve: pt.cve_id };
                if (pt.state === "Low Threat") lowPoints.push(point);
                else if (pt.state === "Medium Threat") medPoints.push(point);
                else highPoints.push(point);
            });

            if (charts.hmmSequence) charts.hmmSequence.destroy();
            const ctxHMM = document.getElementById("chart-hmm-sequence").getContext("2d");
            charts.hmmSequence = new Chart(ctxHMM, {
                type: 'scatter',
                data: {
                    datasets: [
                        {
                            label: 'Low Threat State',
                            data: lowPoints,
                            backgroundColor: '#3b82f6',
                            borderColor: '#1d4ed8',
                            borderWidth: 1,
                            pointRadius: 5
                        },
                        {
                            label: 'Medium Threat State',
                            data: medPoints,
                            backgroundColor: '#10b981',
                            borderColor: '#047857',
                            borderWidth: 1,
                            pointRadius: 5
                        },
                        {
                            label: 'High Threat State',
                            data: highPoints,
                            backgroundColor: '#ef4444',
                            borderColor: '#b91c1c',
                            borderWidth: 1,
                            pointRadius: 5
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top', labels: { color: '#94a3b8' } },
                        tooltip: {
                            backgroundColor: '#0e1322',
                            callbacks: {
                                label: function(ctx) {
                                    return `${ctx.raw.cve}: CVSS ${ctx.raw.y.toFixed(1)}`;
                                }
                            }
                        }
                    },
                    scales: {
                        y: { title: { display: true, text: 'CVSS Score', color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8' } },
                        x: { title: { display: true, text: 'Chronological Vulnerability Timeline Sequence', color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8' } }
                    }
                }
            });

        } catch (err) {
            console.error("Failed to build HMM threat transitions:", err);
        }
    };

    // --- MEMM Transition Simulator slider ---
    const updateMEMMSimulator = async () => {
        const val = parseFloat(elements.memmSlider.value);
        elements.memmValText.textContent = val.toFixed(1);

        try {
            const res = await fetch("/api/analysis/memm", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ next_cvss: val })
            });

            if (!res.ok) return;
            const data = await res.json();

            // Set forecast labels
            elements.memmPredictedLabel.textContent = data.predicted_next_state.toUpperCase();
            
            // Adjust coloring of predicted state
            if (data.predicted_next_state === "Low Threat") {
                elements.memmPredictedLabel.style.color = "var(--accent-blue)";
                elements.memmPredictedLabel.style.textShadow = "var(--glow-blue)";
            } else if (data.predicted_next_state === "Medium Threat") {
                elements.memmPredictedLabel.style.color = "var(--accent-green)";
                elements.memmPredictedLabel.style.textShadow = "var(--glow-green)";
            } else {
                elements.memmPredictedLabel.style.color = "var(--accent-red)";
                elements.memmPredictedLabel.style.textShadow = "var(--glow-red)";
            }

            // Adjust progress widths
            const lowPct = data.probabilities["Low Threat"] || 0;
            const medPct = data.probabilities["Medium Threat"] || 0;
            const highPct = data.probabilities["High Threat"] || 0;

            elements.fillLow.style.width = `${lowPct * 100}%`;
            elements.fillMed.style.width = `${medPct * 100}%`;
            elements.fillHigh.style.width = `${highPct * 100}%`;

            elements.pctLow.textContent = `${(lowPct * 100).toFixed(1)}%`;
            elements.pctMed.textContent = `${(medPct * 100).toFixed(1)}%`;
            elements.pctHigh.textContent = `${(highPct * 100).toFixed(1)}%`;
        } catch (err) {
            console.error("Failed to run MEMM simulator:", err);
        }
    };

    // Bind slider events
    elements.memmSlider.addEventListener("input", updateMEMMSimulator);

    // ==============================================================================
    // 7. TAB: DATABASE EXPLORER (SEARCH, FILTERING, PAGINATION, EXPORT)
    // ==============================================================================

    const loadExplorerData = async () => {
        const query = elements.explorerSearch.value;
        const sev = elements.filterSeverity.value;
        const exp = elements.filterExploit.value;

        try {
            const res = await fetch(`/api/cves?limit=${dbLimit}&offset=${dbOffset}&search=${encodeURIComponent(query)}&severity=${encodeURIComponent(sev)}&exploit=${encodeURIComponent(exp)}`);
            if (!res.ok) return;

            const data = await res.json();
            dbTotal = data.total;

            // Clear table rows
            elements.explorerTable.innerHTML = "";

            if (data.cves.length === 0) {
                elements.explorerTable.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No matching vulnerabilities found. Try resetting the filters.</td></tr>`;
                elements.explorerInfo.textContent = "Showing 0-0 of 0 entries";
                elements.explorerPrev.disabled = true;
                elements.explorerNext.disabled = true;
                return;
            }

            // Populate rows
            data.cves.forEach(row => {
                elements.explorerTable.innerHTML += `
                    <tr>
                        <td class="cve-id-cell">${row.CVE_ID}</td>
                        <td class="text-center font-mono font-bold">${row.Year}</td>
                        <td class="text-center score-cell font-bold text-primary">${row.CVSS_Score.toFixed(1)}</td>
                        <td class="text-center"><span class="badge ${getSeverityPillClass(row.True_Severity)}">${row.True_Severity}</span></td>
                        <td>${row.Exploit_Type}</td>
                        <td>${row.Affected_Component}</td>
                        <td class="desc-cell" title="${row.Description}">${row.Description}</td>
                    </tr>
                `;
            });

            // Pagination details
            const startIdx = dbOffset + 1;
            const endIdx = Math.min(dbTotal, dbOffset + dbLimit);
            elements.explorerInfo.textContent = `Showing ${startIdx}-${endIdx} of ${dbTotal} entries`;

            // Adjust disabling states
            elements.explorerPrev.disabled = dbOffset === 0;
            elements.explorerNext.disabled = endIdx >= dbTotal;

        } catch (err) {
            console.error("Failed to query SQLite explorer data:", err);
        }
    };

    // Filter bindings
    elements.explorerSearch.addEventListener("input", () => {
        dbOffset = 0;
        loadExplorerData();
    });
    elements.filterSeverity.addEventListener("change", () => {
        dbOffset = 0;
        loadExplorerData();
    });
    elements.filterExploit.addEventListener("change", () => {
        dbOffset = 0;
        loadExplorerData();
    });

    // Prev / Next button events
    elements.explorerPrev.addEventListener("click", () => {
        if (dbOffset >= dbLimit) {
            dbOffset -= dbLimit;
            loadExplorerData();
        }
    });
    elements.explorerNext.addEventListener("click", () => {
        if (dbOffset + dbLimit < dbTotal) {
            dbOffset += dbLimit;
            loadExplorerData();
        }
    });

    // CSV Exporter
    elements.exportCsv.addEventListener("click", async () => {
        try {
            const query = elements.explorerSearch.value;
            const sev = elements.filterSeverity.value;
            const exp = elements.filterExploit.value;

            // Fetch ALL matching items (no pagination limit)
            const res = await fetch(`/api/cves?limit=5000&search=${encodeURIComponent(query)}&severity=${encodeURIComponent(sev)}&exploit=${encodeURIComponent(exp)}`);
            if (!res.ok) return;

            const data = await res.json();
            
            // Build CSV rows
            const csvRows = [];
            const headers = ["CVE ID", "Year", "CVSS Score", "Severity", "Exploit Type", "Affected Component", "Description"];
            csvRows.push(headers.join(","));

            data.cves.forEach(row => {
                const escapedDesc = `"${row.Description.replace(/"/g, '""')}"`;
                const csvRow = [
                    row.CVE_ID,
                    row.Year,
                    row.CVSS_Score,
                    row.True_Severity,
                    row.Exploit_Type,
                    row.Affected_Component,
                    escapedDesc
                ];
                csvRows.push(csvRow.join(","));
            });

            const csvContent = "data:text/csv;charset=utf-8," + csvRows.join("\n");
            const encodedUri = encodeURI(csvContent);
            const downloadLink = document.createElement("a");
            downloadLink.setAttribute("href", encodedUri);
            downloadLink.setAttribute("download", "threat_intel_cve_export.csv");
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);

        } catch (err) {
            console.error("CSV download builder failed:", err);
        }
    });

    // ==============================================================================
    // 8. TAB: MODEL CONFIG & LOGS (RETRAIN AND RESETS)
    // ==============================================================================

    // Triggers local retraining of ML architectures
    elements.btnTrain.addEventListener("click", async () => {
        elements.btnTrain.disabled = true;
        elements.btnTrain.querySelector("span").textContent = "Re-training local ML...";
        const spinIcon = elements.btnTrain.querySelector("svg");
        spinIcon.classList.add("spinning");

        elements.trainStatusText.textContent = "Status: Re-fitting trees and Markov transition estimators...";

        try {
            const res = await fetch("/api/models/train", { method: "POST" });
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || "Training failed.");
            }

            const data = await res.json();
            elements.trainStatusText.textContent = "Status: Models successfully persistent and cached!";
            
            // Reload numbers
            fetchSystemStatus();
        } catch (err) {
            elements.trainStatusText.textContent = `Status: Training failed (${err.message})`;
        } finally {
            elements.btnTrain.disabled = false;
            elements.btnTrain.querySelector("span").textContent = "Re-train All Models";
            spinIcon.classList.remove("spinning");
        }
    });

    // --- Individual Model Training Handlers ---
    async function trainIndividualModel(btn, statusEl, endpoint, modelName) {
        btn.disabled = true;
        const originalText = btn.querySelector("span").textContent;
        btn.querySelector("span").textContent = "Training...";
        const icon = btn.querySelector("svg");
        if (icon) icon.classList.add("spinning");
        statusEl.textContent = "Training in progress...";
        statusEl.style.color = "#ffaa3c";

        try {
            const res = await fetch(endpoint, { method: "POST" });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Failed");
            }
            const data = await res.json();
            statusEl.textContent = data.message || `${modelName} trained!`;
            statusEl.style.color = "#00d296";
            fetchSystemStatus();
        } catch (err) {
            statusEl.textContent = `Failed: ${err.message}`;
            statusEl.style.color = "#ff5c5c";
        } finally {
            btn.disabled = false;
            btn.querySelector("span").textContent = originalText;
            if (icon) icon.classList.remove("spinning");
        }
    }

    elements.btnTrainRf.addEventListener("click", () =>
        trainIndividualModel(elements.btnTrainRf, elements.statusRf, "/api/models/train/rf", "Random Forest")
    );
    elements.btnTrainHmm.addEventListener("click", () =>
        trainIndividualModel(elements.btnTrainHmm, elements.statusHmm, "/api/models/train/hmm", "HMM")
    );
    elements.btnTrainMemm.addEventListener("click", () =>
        trainIndividualModel(elements.btnTrainMemm, elements.statusMemm, "/api/models/train/memm", "MEMM")
    );
    elements.btnTrainBert.addEventListener("click", () =>
        trainIndividualModel(elements.btnTrainBert, elements.statusBert, "/api/bert/finetune", "DistilBERT")
    );

    // Credentials Saver
    elements.btnSaveKeys.addEventListener("click", () => {
        const ant = elements.anthropicKey.value.trim();
        const op = elements.openaiKey.value.trim();

        if (ant) localStorage.setItem(KEYS.anthropic, ant);
        else localStorage.removeItem(KEYS.anthropic);

        if (op) localStorage.setItem(KEYS.openai, op);
        else localStorage.removeItem(KEYS.openai);

        alert("API credentials stored securely in local storage cache.");
    });

    // Database Reset Trigger
    elements.btnResetDb.addEventListener("click", async () => {
        if (!confirm("Are you absolutely sure you want to reset the database? This deletes all custom vulnerabilities you analyzed!")) {
            return;
        }

        elements.btnResetDb.disabled = true;
        elements.resetSuccess.classList.add("hidden");

        try {
            const res = await fetch("/api/database/reset", { method: "POST" });
            if (!res.ok) throw new Error("Database reset failed.");

            const data = await res.json();
            
            elements.resetSuccess.classList.remove("hidden");
            elements.resetSuccess.textContent = "Database cleared! Reloaded 100 chronological vulnerability seeds and successfully trained Random Forest, HMM, and ARIMA configurations.";
            
            // Reload page state
            fetchSystemStatus();
            if (document.querySelector(".nav-item.active").getAttribute("data-tab") === "explorer") {
                loadExplorerData();
            }
        } catch (err) {
            alert(`Database reset error: ${err.message}`);
        } finally {
            elements.btnResetDb.disabled = false;
        }
    });

});
