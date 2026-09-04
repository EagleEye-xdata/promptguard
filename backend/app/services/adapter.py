import httpx
from ..models import Target

async def call_target(target:Target,message:str,session_id:str)->str:
    headers={"content-type":"application/json"}
    if target.auth_config_encrypted: headers["authorization"]=target.auth_config_encrypted
    if target.request_format.get("preset","openai_chat")=="generic_json": payload={target.request_format.get("message_field","message"):message,"session_id":session_id}
    else: payload={"model":target.model_name,"messages":[{"role":"user","content":message}]}
    async with httpx.AsyncClient(timeout=30) as client:
        response=await client.post(target.api_endpoint,json=payload,headers=headers); response.raise_for_status(); data=response.json()
    if target.request_format.get("preset","openai_chat")=="generic_json": return str(data.get(target.response_format.get("text_field","response"),""))
    return str(data["choices"][0]["message"]["content"])
