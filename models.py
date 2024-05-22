
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
    SpaceName:List[str]

    @validator('Contact')
    def validate_contact_length(cls,v):
        if not v.isdigit() or len(v)!=10:
            raise ValueError('contact number should be of 10 digits')
        return v
    
    @validator('Access')
    def validate_access(cls,v):
        valid_roles={'Admin','End User'}
        if set(v)-valid_roles:
            raise ValueError(f'Access role must of to be:{",".join(valid_roles)}.Invalid roles:{", ".join(set(v)-valid_roles)}')
        return list(set(v))
    
    @validator('SpaceName')
    def validate_spacename(cls,v):
        valid_spaces={'DevOps','AIML','Data Analysis','Human Resource','Full Stack','Quality Assurance','Business Analysis'}
        if set(v)-valid_spaces:
            raise ValueError(f'SpaceNames must be one of:{",".join(valid_spaces)}. Invalid spaces:{",".join(set(v)-valid_spaces)}')
        return list(set(v))
    
    # @validator('Access')
    # def validate_access(cls, v):
    #     valid_roles = {'Groundfloor': 'Approved','Firstfloor':'Approved'}  # Updated valid_roles
    #     if not all(key in v for key in ['Key', 'value']):
    #         raise ValueError("Access entry must have 'Key' and 'value' keys.")
    #     if v['Key'] not in valid_roles:
    #         raise ValueError(f"Invalid key '{v['Key']}' in access. Keys must be one of: {', '.join(valid_roles)}.")
    #     if v['value'] != valid_roles[v['Key']]:
    #         raise ValueError(f"Invalid value '{v['value']}' for key '{v['Key']}'.")
    #     return v





