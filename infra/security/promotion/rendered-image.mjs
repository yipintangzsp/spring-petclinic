// Extract the target Deployment container image from `helm template` output.
// The production Chart renders every resource as a JSON document (JSON form:
// "image": "core.harbor.domain/..."), while plain charts render YAML form
// (image: core.harbor.domain/...). Structured parsing of the Deployment
// document is preferred; the dual-form regex is only a fallback for output
// where no Deployment document parses. Assertion semantics are unchanged:
// the extracted image must equal the approved candidate or this throws.
const IMAGE_PATTERN = /^core\.harbor\.domain\/petclinic\/petclinic@sha256:[a-f0-9]{64}$/;
export function renderedDeploymentImage(rendered){
  const text=String(rendered);let sawDeployment=false;
  for(const chunk of text.split(/^---[ \t]*$/m)){
    const body=chunk.split("\n").filter(line=>!/^\s*#/.test(line)).join("\n").trim();
    if(!body.startsWith("{"))continue;
    let doc;try{doc=JSON.parse(body);}catch{continue;}
    if(doc?.kind!=="Deployment")continue;
    sawDeployment=true;
    const containers=doc.spec?.template?.spec?.containers;
    if(!Array.isArray(containers))continue;
    const target=containers.find(c=>c?.name==="petclinic")??containers.find(c=>typeof c?.image==="string"&&IMAGE_PATTERN.test(c.image));
    if(typeof target?.image==="string")return target.image;
  }
  if(sawDeployment)return undefined;
  const match=text.match(/"?image"?[ \t]*:[ \t]*"?(core\.harbor\.domain\/petclinic\/petclinic@sha256:[a-f0-9]{64})/);
  return match?match[1]:undefined;
}
export function assertRenderedDeploymentImage(rendered,candidateImage){
  if(renderedDeploymentImage(rendered)!==candidateImage)throw Error("Rendered Deployment image differs from approved candidate");
}
