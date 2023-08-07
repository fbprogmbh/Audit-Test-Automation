"use strict";

let AmountOfNonCompliantRules;
let AmountOfCompliantRules;
let TotalAmountOfRules;
let QuantityCompliance;

let TotalAmountOfSeverityRules;
let AmountOfFailedSeverityRules;
let SeverityCompliance;


function startConditions(){
    let isRiskScoreValue = document.getElementById("riskScore");
    let isMITREValue = document.getElementById("MITRE");

    /* Default-Value: Display summary always at the beginning */
    document.getElementById("summary").style.display = "block";
    
    /* Default-Value: Disable all other tabs at the beginning */
    document.getElementById("foundationData").style.display = "none";
    document.getElementById("references").style.display = "none";
    document.getElementById("settingsOverview").style.display = "none";


    document.getElementById("summaryBtn").style.backgroundColor= '#ff9933';
    document.getElementById("foundationDataBtn").style.backgroundColor = 'transparent';
    document.getElementById("referenceBtn").style.backgroundColor= 'transparent';
    document.getElementById("settingsOverviewBtn").style.backgroundColor= 'transparent';
    
    if(isRiskScoreValue != null){
        document.getElementById("riskScore").style.display = "none";
        document.getElementById("riskScoreBtn").style.backgroundColor= 'transparent';
        /* Initialize necessary variables */
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
        calcDotPosition();
        let severityComplianceCollapseBtn = document.getElementById("severityComplianceCollapse");
        severityComplianceCollapseBtn.addEventListener("click", ()=>{
            if(document.getElementById("severityDetails").style.display == "none"){
                document.getElementById("severityDetails").style.display = "block";
            }
            else{
                document.getElementById("severityDetails").style.display = "none";
            }
        })
    }

    if(isMITREValue != null) {
        document.getElementById("MITRE").style.display = "none";
        document.getElementById("MITREBtn").style.backgroundColor= 'transparent';
        document.getElementById("CISA").style.display = "none";
        document.getElementById("CISABtn").style.backgroundColor= 'transparent';
    }
}


let buttonNumber;

function clickButton(value){
    buttonNumber = parseInt(value);

    /* Disable all content */
    let tabContents = document.getElementsByClassName('tabContent');
    for(let i = 0; i < tabContents.length; i++){
        tabContents.item(i).style.display = "none";
    }

    /* Disable all buttons */
    let buttons = document.getElementsByClassName('navButton');
    for(let i = 0; i < buttons.length; i++){
        buttons.item(i).style.backgroundColor= 'transparent';
    }



    /* Re-Enable fitting content / button */
    switch(buttonNumber){
        case 1:
            document.getElementById("summary").style.display = "block";
            document.getElementById("summaryBtn").style.backgroundColor= '#ff9933';
        break;
        case 2:
            document.getElementById("riskScore").style.display = "block";
            document.getElementById("riskScoreBtn").style.backgroundColor= '#ff9933';
            calcDotPosition();
        break;
        case 3:
            document.getElementById("references").style.display = "block";
            document.getElementById("referenceBtn").style.backgroundColor= '#ff9933';
        break;
        case 4:
            document.getElementById("settingsOverview").style.display = "block";
            document.getElementById("settingsOverviewBtn").style.backgroundColor= '#ff9933';
        break;
        case 5:
            document.getElementById("foundationData").style.display = "block";
            document.getElementById("foundationDataBtn").style.backgroundColor= '#ff9933';
        break;
        case 6:
            document.getElementById("MITRE").style.display = "block";
            document.getElementById("MITREBtn").style.backgroundColor= '#ff9933';
        break;
        case 7:
            document.getElementById("CISA").style.display = "block";
            document.getElementById("CISABtn").style.backgroundColor= '#ff9933';
        break;
    }

}



/* 
Calculate the position of the dot inside the risk matrix; 
Will be calleed, after the user has clicked on Risk Score Button
*/
function calcDotPosition(){

    
    let dotRiskScoreTab = document.getElementById("dotRiskScoreTab");
    let dotSummaryTab = document.getElementById("dotSummaryTab");
    QuantityCompliance = parseFloat(QuantityCompliance);

    let complianceValueQuantity = 0;
    let complianceValueSeverity = 0;

    /*low quantity compliance*/
    if(80 < QuantityCompliance){
        dotRiskScoreTab.style.gridColumnStart = 3;
        dotSummaryTab.style.gridColumnStart = 3;
        complianceValueQuantity = 1;
    }
    /*medium quantity compliance*/
    else if(65 < QuantityCompliance && QuantityCompliance < 80){
        dotRiskScoreTab.style.gridColumnStart = 4;
        dotSummaryTab.style.gridColumnStart = 4;
        complianceValueQuantity = 2;
    }
    /*high quantity compliance*/
    else if(50 < QuantityCompliance && QuantityCompliance < 65){
        dotRiskScoreTab.style.gridColumnStart = 5;
        dotSummaryTab.style.gridColumnStart = 5;
        complianceValueQuantity = 3;
    }
    /*critical quantity compliance*/
    else{
        dotRiskScoreTab.style.gridColumnStart = 6;
        dotSummaryTab.style.gridColumnStart = 6;
        complianceValueQuantity = 4;
    }


    SeverityCompliance = parseInt(AmountOfFailedSeverityRules);
    /*low severity compliance*/
    if(SeverityCompliance == 0){
        dotRiskScoreTab.style.gridRowStart = 4;
        dotSummaryTab.style.gridRowStart = 4;
        complianceValueSeverity = 1;
        

        document.getElementById("complianceStatus").style.padding = "5px 10px";
        document.getElementById("complianceStatus").style.borderRadius = "8px";
        document.getElementById("complianceStatus").style.backgroundColor = "#33cca6";
        document.getElementById("complianceStatus").style.color = "#fff";
        document.getElementById("complianceStatus").style.marginLeft = "6%";
        document.getElementById("complianceStatus").style.fontWeight = "bold";
        document.getElementById("complianceStatus").style.display = "inline";
    }
    /*critical severity compliance*/
    else{
        dotRiskScoreTab.style.gridRowStart = 1;
        dotSummaryTab.style.gridRowStart = 1;
        complianceValueSeverity = 4;
        document.getElementById("complianceStatus").style.padding = "5px 10px";
        document.getElementById("complianceStatus").style.borderRadius = "8px";
        document.getElementById("complianceStatus").style.backgroundColor = "#cc0000";
        document.getElementById("complianceStatus").style.color = "#fff";
        document.getElementById("complianceStatus").style.marginLeft = "6%";
        document.getElementById("complianceStatus").style.fontWeight = "bold";
        document.getElementById("complianceStatus").style.display = "inline";
    }

    let totalComplianceValue = Math.max(complianceValueQuantity, complianceValueSeverity);
    
    let summary = "Current Risk Score on tested System: ";
    let riskResult = document.createElement("p");
    riskResult.style.display = "contents";
    if(totalComplianceValue == 1){
        riskResult.innerText = "Low";
        riskResult.style.backgroundColor = "#548dd6";
    }
    else if(totalComplianceValue == 2){
        riskResult.innerText = "Medium";
        riskResult.style.backgroundColor = "#ffc000";
    }
    else if(totalComplianceValue == 3){
        riskResult.innerText = "High";
        riskResult.style.color = "white";
        riskResult.style.backgroundColor = "#cc0000";
    }
    else{
        riskResult.innerText = "Critical";
        riskResult.style.color = "white";
        riskResult.style.backgroundColor = "purple";
    }
    riskResult.style.display = "inline";
    riskResult.style.padding = "5px 10px";
    riskResult.style.borderRadius = "8px";
    riskResult.style.fontWeight = "bold";
    riskResult.style.margin = "auto";

    let copyRiskResult = riskResult.cloneNode();
    copyRiskResult.innerText  = riskResult.innerText;

    document.getElementById("CurrentRiskScore").textContent = summary;
    document.getElementById("CurrentRiskScore").appendChild(riskResult);
    document.getElementById("CurrentRiskScoreRS").textContent = summary;
    document.getElementById("CurrentRiskScoreRS").appendChild(copyRiskResult);

}

const categoryElements = document.getElementsByClassName('orgMeasure');
function hideMitreTechniques(checkbox){
    if (checkbox.checked) {
        for (let i = 0; i < categoryElements.length; i++) {
            categoryElements[i].style.padding = '0.1em';

            const children = categoryElements[i].querySelectorAll('*');
            for (let j = 0; j < children.length; j++) {
                children[j].style.display = 'none';
            }
        }
    } else {
        for (let i = 0; i < categoryElements.length; i++) {
            categoryElements[i].style.removeProperty('padding');

            const children = categoryElements[i].querySelectorAll('*');
            for (let j = 0; j < children.length; j++) {
                children[j].style.removeProperty('display'); 
            }
        }
    }
}


function hideEverythingButMailTechniques(checkbox) {
    let allOtherNotMailTechniques = document.querySelectorAll('.MITRETechnique:not(.mailVector)');
    if (checkbox.checked) {
        for (let i = 0; i < allOtherNotMailTechniques.length; i++) {
            allOtherNotMailTechniques[i].style.padding = '0.1em';

            const children = allOtherNotMailTechniques[i].querySelectorAll('*');
            for (let j = 0; j < children.length; j++) {
                children[j].style.display = 'none';
            }
        }
    } else {
        for (let i = 0; i < allOtherNotMailTechniques.length; i++) {
            allOtherNotMailTechniques[i].style.removeProperty('padding');

            const children = allOtherNotMailTechniques[i].querySelectorAll('*');
            for (let j = 0; j < children.length; j++) {
                children[j].style.removeProperty('display');
            }
        }
    }
}

