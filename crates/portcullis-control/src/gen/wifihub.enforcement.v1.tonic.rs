// @generated
/// Generated client implementations.
pub mod enforcement_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct EnforcementClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl EnforcementClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> EnforcementClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> EnforcementClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            EnforcementClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn attach(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::EngineFrame>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::ControlFrame>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/Attach",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("wifihub.enforcement.v1.Enforcement", "Attach"));
            self.inner.streaming(req, path, codec).await
        }
        pub async fn grant_session(
            &mut self,
            request: impl tonic::IntoRequest<super::GrantRequest>,
        ) -> std::result::Result<tonic::Response<super::GrantReply>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/GrantSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new("wifihub.enforcement.v1.Enforcement", "GrantSession"),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn revoke_session(
            &mut self,
            request: impl tonic::IntoRequest<super::RevokeRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/RevokeSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "wifihub.enforcement.v1.Enforcement",
                        "RevokeSession",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_session(
            &mut self,
            request: impl tonic::IntoRequest<super::Key>,
        ) -> std::result::Result<tonic::Response<super::SessionInfo>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/GetSession",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new("wifihub.enforcement.v1.Enforcement", "GetSession"),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_sessions(
            &mut self,
            request: impl tonic::IntoRequest<super::ListRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::SessionInfo>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/ListSessions",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new("wifihub.enforcement.v1.Enforcement", "ListSessions"),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        pub async fn stream_events(
            &mut self,
            request: impl tonic::IntoRequest<super::StreamReq>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::SessionEvent>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/StreamEvents",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new("wifihub.enforcement.v1.Enforcement", "StreamEvents"),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        pub async fn health(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::HealthReply>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/Health",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(GrpcMethod::new("wifihub.enforcement.v1.Enforcement", "Health"));
            self.inner.unary(req, path, codec).await
        }
        pub async fn set_enforcement(
            &mut self,
            request: impl tonic::IntoRequest<super::SetEnforcementRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/SetEnforcement",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "wifihub.enforcement.v1.Enforcement",
                        "SetEnforcement",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn set_garden(
            &mut self,
            request: impl tonic::IntoRequest<super::SetGardenRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/SetGarden",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new("wifihub.enforcement.v1.Enforcement", "SetGarden"),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn set_tier_policies(
            &mut self,
            request: impl tonic::IntoRequest<super::SetTierPoliciesRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/SetTierPolicies",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "wifihub.enforcement.v1.Enforcement",
                        "SetTierPolicies",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn set_engine_parameters(
            &mut self,
            request: impl tonic::IntoRequest<super::SetEngineParametersRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/SetEngineParameters",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "wifihub.enforcement.v1.Enforcement",
                        "SetEngineParameters",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_engine_info(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::EngineInfo>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/GetEngineInfo",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "wifihub.enforcement.v1.Enforcement",
                        "GetEngineInfo",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_metrics(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::MetricsReply>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/wifihub.enforcement.v1.Enforcement/GetMetrics",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new("wifihub.enforcement.v1.Enforcement", "GetMetrics"),
                );
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod enforcement_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with EnforcementServer.
    #[async_trait]
    pub trait Enforcement: Send + Sync + 'static {
        /// Server streaming response type for the Attach method.
        type AttachStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::ControlFrame, tonic::Status>,
            >
            + Send
            + 'static;
        async fn attach(
            &self,
            request: tonic::Request<tonic::Streaming<super::EngineFrame>>,
        ) -> std::result::Result<tonic::Response<Self::AttachStream>, tonic::Status>;
        async fn grant_session(
            &self,
            request: tonic::Request<super::GrantRequest>,
        ) -> std::result::Result<tonic::Response<super::GrantReply>, tonic::Status>;
        async fn revoke_session(
            &self,
            request: tonic::Request<super::RevokeRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status>;
        async fn get_session(
            &self,
            request: tonic::Request<super::Key>,
        ) -> std::result::Result<tonic::Response<super::SessionInfo>, tonic::Status>;
        /// Server streaming response type for the ListSessions method.
        type ListSessionsStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::SessionInfo, tonic::Status>,
            >
            + Send
            + 'static;
        async fn list_sessions(
            &self,
            request: tonic::Request<super::ListRequest>,
        ) -> std::result::Result<
            tonic::Response<Self::ListSessionsStream>,
            tonic::Status,
        >;
        /// Server streaming response type for the StreamEvents method.
        type StreamEventsStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::SessionEvent, tonic::Status>,
            >
            + Send
            + 'static;
        async fn stream_events(
            &self,
            request: tonic::Request<super::StreamReq>,
        ) -> std::result::Result<
            tonic::Response<Self::StreamEventsStream>,
            tonic::Status,
        >;
        async fn health(
            &self,
            request: tonic::Request<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::HealthReply>, tonic::Status>;
        async fn set_enforcement(
            &self,
            request: tonic::Request<super::SetEnforcementRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status>;
        async fn set_garden(
            &self,
            request: tonic::Request<super::SetGardenRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status>;
        async fn set_tier_policies(
            &self,
            request: tonic::Request<super::SetTierPoliciesRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status>;
        async fn set_engine_parameters(
            &self,
            request: tonic::Request<super::SetEngineParametersRequest>,
        ) -> std::result::Result<tonic::Response<super::Ack>, tonic::Status>;
        async fn get_engine_info(
            &self,
            request: tonic::Request<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::EngineInfo>, tonic::Status>;
        async fn get_metrics(
            &self,
            request: tonic::Request<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::MetricsReply>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct EnforcementServer<T: Enforcement> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T: Enforcement> EnforcementServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for EnforcementServer<T>
    where
        T: Enforcement,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match req.uri().path() {
                "/wifihub.enforcement.v1.Enforcement/Attach" => {
                    #[allow(non_camel_case_types)]
                    struct AttachSvc<T: Enforcement>(pub Arc<T>);
                    impl<
                        T: Enforcement,
                    > tonic::server::StreamingService<super::EngineFrame>
                    for AttachSvc<T> {
                        type Response = super::ControlFrame;
                        type ResponseStream = T::AttachStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::EngineFrame>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::attach(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = AttachSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/GrantSession" => {
                    #[allow(non_camel_case_types)]
                    struct GrantSessionSvc<T: Enforcement>(pub Arc<T>);
                    impl<T: Enforcement> tonic::server::UnaryService<super::GrantRequest>
                    for GrantSessionSvc<T> {
                        type Response = super::GrantReply;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GrantRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::grant_session(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GrantSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/RevokeSession" => {
                    #[allow(non_camel_case_types)]
                    struct RevokeSessionSvc<T: Enforcement>(pub Arc<T>);
                    impl<
                        T: Enforcement,
                    > tonic::server::UnaryService<super::RevokeRequest>
                    for RevokeSessionSvc<T> {
                        type Response = super::Ack;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RevokeRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::revoke_session(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = RevokeSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/GetSession" => {
                    #[allow(non_camel_case_types)]
                    struct GetSessionSvc<T: Enforcement>(pub Arc<T>);
                    impl<T: Enforcement> tonic::server::UnaryService<super::Key>
                    for GetSessionSvc<T> {
                        type Response = super::SessionInfo;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Key>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::get_session(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetSessionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/ListSessions" => {
                    #[allow(non_camel_case_types)]
                    struct ListSessionsSvc<T: Enforcement>(pub Arc<T>);
                    impl<
                        T: Enforcement,
                    > tonic::server::ServerStreamingService<super::ListRequest>
                    for ListSessionsSvc<T> {
                        type Response = super::SessionInfo;
                        type ResponseStream = T::ListSessionsStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::list_sessions(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = ListSessionsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/StreamEvents" => {
                    #[allow(non_camel_case_types)]
                    struct StreamEventsSvc<T: Enforcement>(pub Arc<T>);
                    impl<
                        T: Enforcement,
                    > tonic::server::ServerStreamingService<super::StreamReq>
                    for StreamEventsSvc<T> {
                        type Response = super::SessionEvent;
                        type ResponseStream = T::StreamEventsStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::StreamReq>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::stream_events(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = StreamEventsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/Health" => {
                    #[allow(non_camel_case_types)]
                    struct HealthSvc<T: Enforcement>(pub Arc<T>);
                    impl<T: Enforcement> tonic::server::UnaryService<super::Empty>
                    for HealthSvc<T> {
                        type Response = super::HealthReply;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Empty>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::health(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = HealthSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/SetEnforcement" => {
                    #[allow(non_camel_case_types)]
                    struct SetEnforcementSvc<T: Enforcement>(pub Arc<T>);
                    impl<
                        T: Enforcement,
                    > tonic::server::UnaryService<super::SetEnforcementRequest>
                    for SetEnforcementSvc<T> {
                        type Response = super::Ack;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SetEnforcementRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::set_enforcement(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = SetEnforcementSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/SetGarden" => {
                    #[allow(non_camel_case_types)]
                    struct SetGardenSvc<T: Enforcement>(pub Arc<T>);
                    impl<
                        T: Enforcement,
                    > tonic::server::UnaryService<super::SetGardenRequest>
                    for SetGardenSvc<T> {
                        type Response = super::Ack;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SetGardenRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::set_garden(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = SetGardenSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/SetTierPolicies" => {
                    #[allow(non_camel_case_types)]
                    struct SetTierPoliciesSvc<T: Enforcement>(pub Arc<T>);
                    impl<
                        T: Enforcement,
                    > tonic::server::UnaryService<super::SetTierPoliciesRequest>
                    for SetTierPoliciesSvc<T> {
                        type Response = super::Ack;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SetTierPoliciesRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::set_tier_policies(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = SetTierPoliciesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/SetEngineParameters" => {
                    #[allow(non_camel_case_types)]
                    struct SetEngineParametersSvc<T: Enforcement>(pub Arc<T>);
                    impl<
                        T: Enforcement,
                    > tonic::server::UnaryService<super::SetEngineParametersRequest>
                    for SetEngineParametersSvc<T> {
                        type Response = super::Ack;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SetEngineParametersRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::set_engine_parameters(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = SetEngineParametersSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/GetEngineInfo" => {
                    #[allow(non_camel_case_types)]
                    struct GetEngineInfoSvc<T: Enforcement>(pub Arc<T>);
                    impl<T: Enforcement> tonic::server::UnaryService<super::Empty>
                    for GetEngineInfoSvc<T> {
                        type Response = super::EngineInfo;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Empty>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::get_engine_info(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetEngineInfoSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/wifihub.enforcement.v1.Enforcement/GetMetrics" => {
                    #[allow(non_camel_case_types)]
                    struct GetMetricsSvc<T: Enforcement>(pub Arc<T>);
                    impl<T: Enforcement> tonic::server::UnaryService<super::Empty>
                    for GetMetricsSvc<T> {
                        type Response = super::MetricsReply;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Empty>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as Enforcement>::get_metrics(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = GetMetricsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", tonic::Code::Unimplemented as i32)
                                .header(
                                    http::header::CONTENT_TYPE,
                                    tonic::metadata::GRPC_CONTENT_TYPE,
                                )
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: Enforcement> Clone for EnforcementServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: Enforcement> tonic::server::NamedService for EnforcementServer<T> {
        const NAME: &'static str = "wifihub.enforcement.v1.Enforcement";
    }
}
