
build_nt:
	mvn clean package -DskipTests

image: build_nt
	docker build -f src/main/docker/Dockerfile.jvm -t nttdata-dach-techblog/secrets-demo .

deploy_std: image
	kubectl apply -f src/main/k8s/standard

deploy_sealed: image
	./deploy_sealed.sh	

deploy_eso: image
	./deploy_eso.sh	

clean:
	kubectl delete namespace/nttdata-dach-techblog-secrets-demo