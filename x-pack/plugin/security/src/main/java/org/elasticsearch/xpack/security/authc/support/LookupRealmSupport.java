/*
 * ELASTICSEARCH CONFIDENTIAL
 * __________________
 *
 *  [2018] Elasticsearch Incorporated. All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Elasticsearch Incorporated and its suppliers,
 * if any.  The intellectual and technical concepts contained
 * herein are proprietary to Elasticsearch Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Elasticsearch Incorporated.
 */

package org.elasticsearch.xpack.security.authc.support;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.Strings;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.Realm;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.xpack.core.security.authc.support.LookupRealmSettings;
import org.elasticsearch.xpack.core.security.user.User;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class LookupRealmSupport {

    private final List<Realm> lookupRealms;

    public LookupRealmSupport(Iterable<Realm> allRealms, RealmConfig config) {
        final List<String> lookupRealms = LookupRealmSettings.LOOKUP_REALMS.get(config.settings());
        this.lookupRealms = resolveRealms(allRealms, lookupRealms);
    }

    public void lookupUser(String username, Consumer<ActionListener<AuthenticationResult>> defaultAuthentication,
                           ActionListener<AuthenticationResult> resultListener) {
        if (lookupRealms.isEmpty()) {
            defaultAuthentication.accept(resultListener);
        } else {
            new LookupListener(username, resultListener).lookupUser();
        }
    }

    private List<Realm> resolveRealms(Iterable<Realm> allRealms, List<String> lookupRealms) {
        final List<Realm> result = new ArrayList<>(lookupRealms.size());
        for (String name : lookupRealms) {
            Realm realm = findRealm(name, allRealms);
            if (realm == null) {
                throw new IllegalStateException("configured lookup realm [" + name + "] does not exist");
            }
            result.add(realm);
        }
        assert result.size() == lookupRealms.size();
        return result;
    }

    private Realm findRealm(String name, Iterable<Realm> allRealms) {
        for (Realm realm : allRealms) {
            if (name.equals(realm.name())) {
                return realm;
            }
        }
        return null;
    }


    private final class LookupListener implements ActionListener<User> {
        private final String username;
        private final ActionListener<AuthenticationResult> resultListener;
        private final Iterator<Realm> iterator;

        private LookupListener(String username, ActionListener<AuthenticationResult> resultListener) {
            this.username = username;
            this.resultListener = resultListener;
            this.iterator = LookupRealmSupport.this.lookupRealms.iterator();
        }

        public void lookupUser() {
            assert iterator.hasNext() : "Iterator has finished";
            iterator.next().lookupUser(username, this);
        }

        @Override
        public void onResponse(User user) {
            if (user != null) {
                resultListener.onResponse(AuthenticationResult.success(user));
            } else if (iterator.hasNext()) {
                lookupUser();
            } else {
                resultListener.onResponse(AuthenticationResult.unsuccessful("the principal [" + username
                    + "] was authenticated, but no user could be found in realms [" +
                    Strings.collectionToDelimitedString(LookupRealmSupport.this.lookupRealms, ",") + "]", null));
            }
        }

        @Override
        public void onFailure(Exception e) {
            resultListener.onFailure(e);
        }
    }

}
