/*
 * Copyright (c) 2008-2009 Tomas Varaneckas
 * http://www.varaneckas.com
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package com.googlecode.gmail4j.http;

import java.io.IOException;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.Proxy.Type;

import com.googlecode.gmail4j.GmailConnection;
import com.googlecode.gmail4j.GmailException;
import com.googlecode.gmail4j.auth.Credentials;
import com.googlecode.gmail4j.auth.GmailHttpAuthenticator;

/**
 * {@link GmailConnection} implementation that uses HTTP transport. 
 * <p>
 * It is {@link Proxy} aware. Example use:
 * <p><blockquote><pre>
 *     GmailClient client = //...
 *     GmailConnection conn = new HttpGmailConnection(gmailUser, gmailPass);
 *     client.setConnection(conn);
 * </pre></blockquote><p>
 * When using with {@link Proxy}:
 * <p><blockquote><pre>
 *     GmailClient client = //...
 *     HttpGmailConnection conn = new HttpGmailConnection(gmailUser, gmailPass);
 *     conn.setProxy(proxyHost, proxyPort);
 *     conn.setProxyCredentials(proxyUser, proxyPass);
 *     client.setConnection(conn);
 * </pre></blockquote><p>
 * 
 * @see Credentials
 * @see GmailConnection
 * @see Proxy
 * @see RssGmailClient
 * @author Tomas Varaneckas &lt;tomas.varaneckas@gmail.com&gt;
 * @version $Id$
 * @since 0.2
 */
public class HttpGmailConnection extends GmailConnection {
    
    /**
     * Argless constructor.
     * <p>
     * Set credentials manually with {@link #setLoginCredentials(Credentials)}
     * or {@link #setLoginCredentials(String, char[])}.
     */
    public HttpGmailConnection() {
    }
    
    /**
     * Constructor with Gmail {@link Credentials}
     * 
     * @param loginCredentials Gmail login
     * @throws GmailException if provided credentials are empty
     */
    public HttpGmailConnection(final Credentials loginCredentials) {
        super(loginCredentials);
    }
    
    /**
     * Convenience constructor with Gmail {@link Credentials}
     * 
     * @param username Gmail username
     * @param password Gmail password
     * @throws GmailException if provided credentials are empty
     */    
    public HttpGmailConnection(final String username, final char[] password) {
        super(username, password);
    }

    /**
     * HTTP connection URL
     * 
     * @see #setUrl(String)
     */
    private URL url;
    
    /**
     * HTTP Proxy for making a connection.
     * 
     * @see #setProxy(Proxy)
     * @see #setProxy(String, int)
     * @see #getProxy()
     */
    private Proxy proxy = null;    
    
    /**
     * HTTP Proxy {@link Credentials}
     * 
     * @see #proxy
     * @see #setProxyCredentials(Credentials)
     * @see #setProxyCredentials(String, char[])
     */
    private Credentials proxyCredentials = null;
    
    /**
     * Sets {@link #url} for this HTTP connection
     * 
     * @param url URL of Gmail service you want to connect to
     * @throws GmailException if URL is malformed
     */
    public void setUrl(final String url) {
        try {
            this.url = new URL(url);
        } catch (final MalformedURLException e) {
            throw new GmailException("Failed creating Gmail connection", e);
        }
    }
    
    /**
     * Opens {@link URLConnection} for getting data from Gmail RSS.
     * <p>
     * May use {@link Proxy} if one is defined
     * 
     * @see #proxy
     * @return connection
     * @throws IOException if opening a connection fails
     */
    public URLConnection openConnection() {
        Authenticator.setDefault(
                new GmailHttpAuthenticator(loginCredentials, proxyCredentials));
        try {
            if (proxy != null) {
                return url.openConnection(proxy); 
            } else {
                return url.openConnection();
            }
        } catch (final IOException e) {
            throw new GmailException("Failed opening Gmail connection", e);
        }
    }
    
    /**
     * Sets the {@link #proxy}
     * 
     * @param proxy Proxy for RSS connection
     */
    public void setProxy(final Proxy proxy) {
        this.proxy = proxy;
    }
    
    /**
     * A convenience method for setting HTTP {@link #proxy}
     * 
     * @param proxyHost Proxy host
     * @param proxyPort Proxy port
     */
    public void setProxy(final String proxyHost, final int proxyPort) {
        this.proxy = new Proxy(Type.HTTP, InetSocketAddress
                .createUnresolved(proxyHost, proxyPort));
    }
    
    /**
     * Sets {@link #proxyCredentials}
     * 
     * @param proxyCredentials Proxy authentication
     */
    public void setProxyCredentials(final Credentials proxyCredentials) {
        this.proxyCredentials = proxyCredentials;
    }
    
    /**
     * A convenience method for setting {@link #proxyCredentials}
     * 
     * @param username Proxy auth username
     * @param password Proxy auth password
     */
    public void setProxyCredentials(final String username, final char[] password) {
        setProxyCredentials(new Credentials(username, password));
    }
    
    /**
     * Gets the {@link #proxy}
     * 
     * @return Proxy or null if unavailable
     */
    public Proxy getProxy() {
        return this.proxy;
    }
    
    @Override
    protected void finalize() throws Throwable {
        loginCredentials.dispose();
        if (proxyCredentials != null) {
            proxyCredentials.dispose();
        }
        super.finalize();
    }
}
