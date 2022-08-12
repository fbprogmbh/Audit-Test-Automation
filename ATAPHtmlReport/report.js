function startConditions(){
    document.getElementById("riskScore").style.display = "none";
    document.getElementById("summary").style.display = "block";
    document.getElementById("summaryBtn").style.backgroundColor= '#ff9933';
    document.getElementById("riskScoreBtn").style.backgroundColor= 'transparent';
}

function clickSummaryBtn() {
    document.getElementById("riskScore").style.display = "none";
    document.getElementById("summary").style.display = "block";
    document.getElementById("summaryBtn").style.backgroundColor= '#ff9933';
    document.getElementById("riskScoreBtn").style.backgroundColor= 'transparent';
}

function clickRiskScoreBtn() {
    document.getElementById("riskScoreBtn").style.backgroundColor= '#ff9933';
    document.getElementById("summaryBtn").style.backgroundColor= 'transparent';
    document.getElementById("riskScore").style.display = "block";
    document.getElementById("summary").style.display = "none";
}
