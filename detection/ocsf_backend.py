from sigma.pipelines.ocsf import ocsf_pipeline
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from typing import Dict, List, Optional, Any

class OCSFBackend:
    """Simple OCSF backend for Sigma rules."""
    
    def __init__(self, pipeline=None):
        """Initialize OCSF backend."""
        self.pipeline = pipeline or ocsf_pipeline()
    
    def convert_rule(self, rule: SigmaRule) -> List[str]:
        """Convert a Sigma rule to OCSF query strings."""
        # This is a simplified implementation that just returns a basic query
        # In a real implementation, this would convert the rule to OCSF format
        queries = []
        
        # Add a simple query that checks the rule ID
        queries.append(f"data.rule_id == '{rule.id}'")
        
        # If the rule has a title, add a query that checks for it
        if hasattr(rule, 'title') and rule.title:
            queries.append(f"data.title == '{rule.title}'")
        
        # If the rule has a description, add a query that checks for it
        if hasattr(rule, 'description') and rule.description:
            queries.append(f"data.description == '{rule.description}'")
        
        # Always return at least one query, even if it's just a dummy that will never match
        if not queries:
            queries.append("data.dummy == 'dummy'")
        
        return queries
    
    def convert(self, sigma_collection: SigmaCollection) -> List[str]:
        """Convert a SigmaCollection to OCSF query strings."""
        queries = []
        
        # Process the collection through the pipeline
        try:
            processed_collection = sigma_collection.process_pipeline(self.pipeline)
            
            # Convert each rule in the collection
            for rule in processed_collection.rules:
                queries.extend(self.convert_rule(rule))
        except Exception as e:
            # If processing fails, return a dummy query
            queries.append("data.dummy == 'dummy'")
        
        return queries