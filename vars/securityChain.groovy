// Standard security-chain entry (2026-11-13 extraction). Pipelines pass only a
// project name plus per-build inputs; the bundled project config instance
// (resources/security-manager/projects/<project>.json) supplies the project
// identity, mode/profile defaults and the engine binding. The frozen V1 entry
// (vars/securityManager.groovy, pinned in the command-parent frozen baseline)
// stays byte-identical behind this interface and receives the exact legacy
// argument set for configured projects. Calls without a bundled project
// config pass through to the legacy entry unchanged.
def call(Map cfg=[:]) {
 def projectCfg=[:]
 String projectName=cfg.project ?: (cfg.adapter=='petclinic' ? 'petclinic' : null)
 if (projectName) { try { projectCfg=readJSON(text:libraryResource('security-manager/projects/'+projectName+'.json'),returnPojo:true) } catch(Exception ignored) { projectCfg=[:] } }
 if (!projectCfg) return securityManager(cfg)
 Map delegated=[:]
 delegated.putAll(cfg)
 if (projectCfg.mode && delegated.mode==null) delegated.mode=projectCfg.mode
 if (projectCfg.profile && delegated.profile==null) delegated.profile=projectCfg.profile
 if (projectCfg.adapter && delegated.adapter==null) delegated.adapter=projectCfg.adapter
 return securityManager(delegated)
}
