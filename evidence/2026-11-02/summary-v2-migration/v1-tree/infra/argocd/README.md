# Application Controller 资源修正

2026-10-19 首次安装 Argo Rollouts CRD时，Application Controller原512Mi内存limit发生OOMKilled/exit137，restart54；同期日志显示更新Kubernetes OpenAPI schema。重启后metrics-server约368Mi，此证据支持该次CRD发现/缓存过程存在瞬时内存不足，不等于证明所有历史54次重启都由同一原因引起。

`controller-resources-patch.json` 把requests128→384Mi、limit512→768Mi，并设置Go软内存目标GOMEMLIMIT=512MiB，CPU保持50m/500m。完整预算多计256Mi内存requests及256Mi内存limit；停止线不变。该补丁不属于Petclinic父应用自动同步目录，须经现有完整流水线成功后受控应用到**已有**StatefulSet，再观察应用比较、同步和新实验期间有无新增OOM。保留原有kubeconfig、镜像、PVC与其他环境变量。

```sh
kubectl -n argocd patch sts argocd-application-controller --type=strategic --patch-file infra/argocd/controller-resources-patch.json
kubectl -n argocd rollout status sts/argocd-application-controller --timeout=180s
kubectl -n argocd top pod argocd-application-controller-0
kubectl -n argocd logs argocd-application-controller-0 --tail=100
```

一次短时验收不能证明长时间无泄漏。后续Helm升级须携带相同controller.resources与controller.extraEnv设置，避免模板升级退回原值。没有把现有所有Argo组件重新纳入新管理器，不能声称整个Argo安装已经完全GitOps化。
