from uuid import uuid4
from datetime import datetime
from pydantic import BaseModel,Field,validator
from typing import List, Optional,Dict

class UserModel(BaseModel):
    Id:str=Field(default_factory=lambda: str(uuid4()))
    FirstName:str
    LastName:str
    EmpId:str
    Email:str
    Contact:str
    # Access:List[Dict[str, str]]
    Access:List[str]
    JobTitle:str
    EmployeeType:str
    # SpaceName:List[str]
    SpaceName: str
    Role: str

    @validator('Contact')
    def validate_contact_length(cls,v):
        if not v.isdigit() or len(v)!=10:
            raise ValueError('contact number should be of 10 digits')
        return v
    
    @validator('Role')
    def validate_roles(cls,v):
        valid_roles={'Admin','User'}
        if v not in valid_roles:
            raise ValueError(f'Role must be one of:{",".join(valid_roles)}. Invalid role:{v}')
        return v
    
    @validator('Access')
    def validate_access(cls,v):
        valid_access={"Recent_Openings_View","Recent_Openings_JobOpenings_View","Recent_Openings_JobOpenings_Write",
                     "Events_View","Policies_View","Employees_View","Recruitment_View","New_Recruitment_View_And_Write",
                     "New_Recruitment_Write","Recruitment_Status_View_And_write","Recruitment_Status_Write",
                     "On_Boarding_View_And_Write","On_Boarding_Write","New_Job_View_And_Write","New_Job_Write",
                     "Interviewer_Board_View","Interviewer_Board_write","Blogs_View_And_Write","Blogs_Write","Write_FeedBack_View",
                     "Write_FeedBack_View_And_Write","View_FeedBack_View","View_FeedBack_Write","Projects_View_And_Write",
                     "Projects_Write","Reports_View_And_Write","Reports_Write"}
        if set(v)-valid_access:
            raise ValueError(f'Access role must of to be:{",".join(valid_access)}.Invalid roles:{", ".join(set(v)-valid_access)}')
        return list(set(v))
