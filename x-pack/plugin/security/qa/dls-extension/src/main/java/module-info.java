module org.elasticsearch.test.dls {
    requires org.elasticsearch.base;
    requires org.elasticsearch.server;
    requires org.elasticsearch.xcore;
    requires org.elasticsearch.security;
    requires org.elasticsearch.logging;

    provides org.elasticsearch.xpack.core.security.SecurityExtension
        with
            org.elasticsearch.xpack.security.authz.dls.extension.TestDlsSecurityExtension;
}
