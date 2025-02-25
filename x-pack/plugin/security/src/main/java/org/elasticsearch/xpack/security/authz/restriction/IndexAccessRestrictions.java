/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import org.elasticsearch.xcontent.ToXContentFragment;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xpack.core.security.authc.Subject;
import org.elasticsearch.xpack.core.security.authz.permission.Role;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Stream;

public class IndexAccessRestrictions implements ToXContentObject {

    public static final IndexAccessRestrictions EMPTY = new IndexAccessRestrictions(List.of());

    public interface SubjectList extends Predicate<Subject>, ToXContentFragment {}

    public record Restriction(String name, SubjectList appliesTo, IndexRestrictedRole.IndexAccessLimit accessLimit) {}

    private final List<Restriction> restrictions;

    public IndexAccessRestrictions(List<Restriction> restrictions) {
        this.restrictions = restrictions;
    }

    public int size() {
        return restrictions.size();
    }

    public Role getRestrictedRole(Subject subject, Role baseRole) {
        List<IndexRestrictedRole.IndexAccessLimit> indexLimits = this.restrictions.stream()
            .filter(restriction -> restriction.appliesTo.test(subject))
            .map(Restriction::accessLimit)
            .toList();

        if (indexLimits.isEmpty()) {
            return baseRole;
        } else {
            return new IndexRestrictedRole(restrictions.stream().map(Restriction::name).toArray(String[]::new), baseRole, indexLimits);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        for (Restriction restriction : restrictions) {
            builder.startObject(restriction.name);
            restriction.appliesTo.toXContent(builder, params);
            builder.field("indices", restriction.accessLimit.indexNames());
            builder.field("privileges", restriction.accessLimit.allowedPrivilege().name());
            builder.endObject();
        }

        return builder.endObject();
    }

    public static SubjectList matchRoles(Set<String> roles) {
        return new SubjectList() {
            @Override
            public boolean test(Subject subject) {
                if (subject.getType() == Subject.Type.USER) {
                    return Stream.of(subject.getUser().roles()).anyMatch(roles::contains);
                }
                return false;
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
                return builder.startObject().field("roles", roles).endObject();
            }
        };
    }

    public static SubjectList negate(SubjectList complement) {
        return new SubjectList() {
            @Override
            public boolean test(Subject subject) {
                return complement.test(subject) == false;
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
                return builder.field("exclude", complement);
            }
        };
    }

    public static final SubjectList ALL_SUBJECTS = new SubjectList() {
        @Override
        public boolean test(Subject subject) {
            return true;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) {
            return null;
        }
    };
}
