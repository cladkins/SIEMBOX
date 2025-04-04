from sigma.backends.base import TextQueryBackend
from sigma.conversion.base import TextQueryBackendState
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import SigmaString, SigmaNumber, SigmaRegularExpression
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.pipelines.ocsf import ocsf_pipeline
from typing import ClassVar, Dict, List, Optional, Pattern, Tuple, Union

class OCSFBackend(TextQueryBackend):
    """OCSF backend for Sigma rules."""
    
    # Class attributes
    name: ClassVar[str] = "OCSF Backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "OCSF query format",
    }

    def __init__(self, pipeline=None):
        """Initialize OCSF backend."""
        super().__init__(pipeline or ocsf_pipeline())
        self.pipeline = pipeline or ocsf_pipeline()

    def convert_condition_field_eq_val(self, cond: ConditionItem, state: ConversionState) -> str:
        """Convert field = value condition."""
        field = cond.field
        value = cond.value
        
        if isinstance(value, SigmaString):
            return f"{field} == '{value.s}'"
        elif isinstance(value, SigmaNumber):
            return f"{field} == {value.number}"
        elif isinstance(value, SigmaRegularExpression):
            return f"{field} matches '{value.regexp}'"
        else:
            return f"{field} == {value}"

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> str:
        """Convert AND condition."""
        return " && ".join([self.convert_condition(arg, state) for arg in cond.args])

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> str:
        """Convert OR condition."""
        return " || ".join([self.convert_condition(arg, state) for arg in cond.args])

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> str:
        """Convert NOT condition."""
        return f"!({self.convert_condition(cond.args[0], state)})"

    def finalize_query(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        """Finalize query."""
        return query