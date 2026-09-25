# 대시보드 실행 환경. 인터프리터를 고정해 "어느 python 이 활성화됐나"를 없앤다.
#
# 점검 대상(Juice Shop·DVWA·reflection_lab)은 이 이미지에 넣지 않는다. 대상은 각자
# 띄우고, 대시보드는 host.docker.internal 로 호스트의 대상에 닿는다.
FROM python:3.12-slim

# Playwright 는 일부러 넣지 않는다. 브라우저 바이너리가 이미지를 1GB 넘게 키우는데
# 이 대시보드는 브라우저 Runtime 을 쓰지 않는다. browser XSS 검증을 켤 때 별도
# 단계로 추가한다.
RUN pip install --no-cache-dir beautifulsoup4==4.15.0 lxml==6.1.3

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    HACKLIPSE_DASHBOARD_CONTAINER=1

WORKDIR /app

# compose 는 같은 경로를 bind mount 로 덮어쓴다. 여기 COPY 하는 이유는 compose 없이
# `docker run` 만으로도 돌아가게 하기 위해서다.
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY web/ ./web/

RUN useradd --create-home --uid 10001 hacklipse
USER hacklipse

EXPOSE 8899

# 컨테이너 안에서는 eth0 로 들어오는 요청을 받아야 Docker 의 포트 공개가 동작한다.
# 밖으로 얼마나 열리는지는 publish 주소가 정한다 — compose 는 127.0.0.1 로 묶는다.
CMD ["python", "scripts/serve_dashboard.py", "--bind", "0.0.0.0"]
