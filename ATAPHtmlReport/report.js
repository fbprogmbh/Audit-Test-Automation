let AmountOfNonCompliantRules;
let AmountOfCompliantRules;
let TotalAmountOfRules;
let QuantityCompliance;

let TotalAmountOfSeverityRules;
let AmountOfFailedSeverityRules;
let SeverityCompliance;


function startConditions(){
    document.getElementById("riskScore").style.display = "none";
    document.getElementById("summary").style.display = "block";
    document.getElementById("summaryBtn").style.backgroundColor= '#ff9933';
    document.getElementById("riskScoreBtn").style.backgroundColor= 'transparent';

    AmountOfNonCompliantRules = document.getElementById("AmountOfNonCompliantRules").textContent;
    document.getElementById("AmountOfNonCompliantRules").hidden = true;

    AmountOfCompliantRules = document.getElementById("AmountOfCompliantRules").textContent;
    document.getElementById("AmountOfCompliantRules").hidden = true;

    TotalAmountOfRules = document.getElementById("TotalAmountOfRules").textContent;
    document.getElementById("TotalAmountOfRules").hidden = true;

    QuantityCompliance = document.getElementById("QuantityCompliance").textContent;
    document.getElementById("QuantityCompliance").hidden = true;




    TotalAmountOfSeverityRules = document.getElementById("TotalAmountOfSeverityRules").textContent;
    document.getElementById("TotalAmountOfSeverityRules").hidden = true;

    AmountOfFailedSeverityRules = document.getElementById("AmountOfFailedSeverityRules").textContent;
    document.getElementById("AmountOfFailedSeverityRules").hidden = true;
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
    calcDotPosition();
}


/* 
Calculate the position of the dot inside the risk matrix; 
Will be calleed, after the user has clicked on Risk Score Button
*/
function calcDotPosition(){

    let dot = document.getElementById("dot");
    QuantityCompliance = parseFloat(QuantityCompliance);

    let complianceValueQuantity = 0;
    let complianceValueSeverity = 0;

    /*low quantity compliance*/
    if(85 < QuantityCompliance){
        dot.style.gridColumnStart = 3;
        complianceValueQuantity = 1;
    }
    /*medium quantity compliance*/
    else if(70 < QuantityCompliance && QuantityCompliance < 85){
        dot.style.gridColumnStart = 4;
        complianceValueQuantity = 2;
    }
    /*high quantity compliance*/
    else if(55 < QuantityCompliance && QuantityCompliance < 70){
        dot.style.gridColumnStart = 5;
        complianceValueQuantity = 3;
    }
    /*critical quantity compliance*/
    else{
        dot.style.gridColumnStart = 6;
        complianceValueQuantity = 4;
    }


    SeverityCompliance = parseInt(AmountOfFailedSeverityRules);
    /*low severity compliance*/
    if(SeverityCompliance == 0){
        dot.style.gridRowStart = 4;
        complianceValueSeverity = 1;
    }
    /*critical severity compliance*/
    else{
        dot.style.gridRowStart = 1;
        complianceValueSeverity = 4;
    }

    let totalComplianceValue = Math.max(complianceValueQuantity, complianceValueSeverity);
    
    let summary;
    if(totalComplianceValue == 1){
        summary = "Current Risk score on your System: Low";
    }
    else if(totalComplianceValue == 2){
        summary = "Current Risk score on your System: Medium";
    }
    else if(totalComplianceValue == 3){
        summary = "Current Risk score on your System: High";
    }
    else{
        summary = "Current Risk score on your System: Critical";
    }
    document.getElementById("CurrentRiskScore").textContent = summary;

}