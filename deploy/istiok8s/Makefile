.PHONY: install_app upgrade_app uninstall_app

install_app:
	-kubectl delete namespace istiok8s
	kubectl create namespace istiok8s
	kubectl label namespace istiok8s istio-injection=enabled
	helm install istiok8s . -n istiok8s

upgrade_app:
	helm upgrade istiok8s . -n istiok8s

uninstall_app:
	helm uninstall istiok8s  -n istiok8s
	kubectl delete namespace istiok8s

.PHONY: open_dashboard print_host
open_dashboard:
	istioctl dashboard kiali

host=$(shell kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
port=$(shell kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
https_port=$(shell kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].port}')
base_url=$(host):$(port)
print_host:
	@echo "base url is $(base_url)"




