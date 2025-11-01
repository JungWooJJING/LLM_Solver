import json
from datetime import datetime
from openai import OpenAI
from templates.prompting import CTFSolvePrompt
from utility.core_utility import Core
from rich.console import Console

core = Core()
console = Console()

class ScenarioAgent:
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def create_scenario(self, challenge_info: dict, state: dict, option: str) -> dict:
        """
        Create a scenario based on challenge information and current state
        """
        prompt = [
            {"role": "developer", "content": CTFSolvePrompt.scenario_prompt},
            {"role": "user", "content": json.dumps({
                "challenge": challenge_info,
                "state": state,
                "option": option
            }, ensure_ascii=False)}
        ]

        try:
            res = self.client.chat.completions.create(model=self.model, messages=prompt)
            raw = res.choices[0].message.content
            scenario = json.loads(raw)
            
            # Add timestamp
            scenario["created_at"] = datetime.now().isoformat()
            
            # Save scenario
            core.save_json(fileName="scenario.json", obj=scenario)
            console.print("=== Scenario Created ===", style="bold green")
            console.print(f"Scenario ID: {scenario.get('scenario_id', 'unknown')}")
            console.print(f"Objective: {scenario.get('objective', 'unknown')}")
            console.print(f"Milestones: {len(scenario.get('success_milestones', []))}")
            
            return scenario
            
        except Exception as e:
            console.print(f"Error creating scenario: {e}", style="red")
            return {}

    def track_progress(self, scenario: dict, state: dict, latest_results: dict) -> dict:
        """
        Track progress against scenario milestones
        """
        prompt = [
            {"role": "developer", "content": CTFSolvePrompt.scenario_tracker_prompt},
            {"role": "user", "content": json.dumps({
                "scenario": scenario,
                "state": state,
                "latest_results": latest_results
            }, ensure_ascii=False)}
        ]

        try:
            res = self.client.chat.completions.create(model=self.model, messages=prompt)
            raw = res.choices[0].message.content
            progress = json.loads(raw)
            
            # Add timestamp
            progress["tracked_at"] = datetime.now().isoformat()
            
            # Save progress
            core.save_json(fileName="scenario_progress.json", obj=progress)
            
            # Update scenario with new milestone statuses
            self._update_scenario_milestones(scenario, progress)
            
            console.print("=== Scenario Progress Updated ===", style="bold green")
            console.print(f"Overall Progress: {progress.get('scenario_progress', {}).get('overall_progress', 'unknown')}")
            
            return progress
        except Exception as e:
            console.print(f"Error tracking progress: {e}", style="red")
            return {}

    def _update_scenario_milestones(self, scenario: dict, progress: dict):
        """
        Update scenario milestone statuses based on progress tracking
        """
        milestone_updates = progress.get("milestone_updates", [])
        
        for update in milestone_updates:
            milestone_id = update.get("milestone_id")
            new_status = update.get("new_status")
            
            # Find and update the milestone in scenario
            for milestone in scenario.get("success_milestones", []):
                if milestone.get("milestone_id") == milestone_id:
                    milestone["status"] = new_status
                    milestone["last_updated"] = datetime.now().isoformat()
                    break

    def get_next_actions(self, scenario: dict, progress: dict) -> list:
        """
        Get recommended next actions based on scenario and progress
        """
        return progress.get("next_actions", [])

    def check_milestone_completion(self, scenario: dict, milestone_id: str) -> bool:
        """
        Check if a specific milestone is completed
        """
        for milestone in scenario.get("success_milestones", []):
            if milestone.get("milestone_id") == milestone_id:
                return milestone.get("status") == "completed"
        return False

    def get_completed_milestones(self, scenario: dict) -> list:
        """
        Get list of completed milestone IDs
        """
        completed = []
        for milestone in scenario.get("success_milestones", []):
            if milestone.get("status") == "completed":
                completed.append(milestone.get("milestone_id"))
        return completed

    def get_current_milestone(self, scenario: dict) -> dict:
        """
        Get the current active milestone
        """
        for milestone in scenario.get("success_milestones", []):
            if milestone.get("status") == "in_progress":
                return milestone
        return {}

    def print_scenario_summary(self, scenario: dict):
        """
        Print a summary of the current scenario
        """
        console.print("\n=== Scenario Summary ===", style="bold blue")
        console.print(f"Objective: {scenario.get('objective', 'Unknown')}")
        console.print(f"Challenge Type: {scenario.get('challenge_type', 'Unknown')}")
        console.print(f"Difficulty: {scenario.get('estimated_difficulty', 'Unknown')}")
        
        milestones = scenario.get("success_milestones", [])
        completed = len([m for m in milestones if m.get("status") == "completed"])
        total = len(milestones)
        
        console.print(f"Progress: {completed}/{total} milestones completed")
        
        # Show current milestone
        current = self.get_current_milestone(scenario)
        if current:
            console.print(f"Current Milestone: {current.get('name', 'Unknown')}")
            console.print(f"Description: {current.get('description', 'No description')}")
        
        # Show next actions
        progress_file = core.load_json("scenario_progress.json", default={})
        next_actions = progress_file.get("next_actions", [])
        if next_actions:
            console.print("\n=== Next Actions ===", style="bold yellow")
            for i, action in enumerate(next_actions[:3], 1):  # Show top 3
                console.print(f"{i}. {action.get('action', 'Unknown action')}")
                console.print(f"   Target: {action.get('target_milestone', 'Unknown')}")
                console.print(f"   Priority: {action.get('priority', 'Unknown')}")
