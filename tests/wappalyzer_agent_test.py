"""Unittests for Wappalyzer agent."""
OUPUT = '{"urls":{"https://ostorlab.co/":{"status":301},"https://www.ostorlab.co/":{"status":200}},' \
        '"technologies":[{"slug":"node-js","name":"Node.js","confidence":100,"version":null,"icon":' \
        '\"node.js.png","website":"http://nodejs.org","cpe":"cpe:/a:nodejs:node.js","categories":[{' \
        '"id":27,"slug":"programming-languages","name":"Programming languages"}]},{"slug":"vuetify",' \
        '"name":"Vuetify","confidence":100,"version":null,"icon":"Vuetify.svg","website":' \
        '"https://vuetifyjs.com","cpe":null,"categories":[{"id":66,"slug":"ui-frameworks","name":' \
        '"UI frameworks"}]},{"slug":"videojs","name":"VideoJS","confidence":100,"version":null,"icon":' \
        '"VideoJS.svg","website":"http://videojs.com","cpe":null,"categories":[{"id":14,"slug":' \
        '"video-players","name":"Video players"}]},{"slug":"vue-js","name":"Vue.js","confidence":100,' \
        '"version":null,"icon":"vue.svg","website":"https://vuejs.org","cpe":null,"categories":[{"id":' \
        '12,"slug":"javascript-frameworks","name":"JavaScript frameworks"}]},{"slug":"nuxt-js","name":' \
        '"Nuxt.js","confidence":100,"version":null,"icon":"Nuxt.js.svg","website":"https://nuxtjs.org",' \
        '"cpe":null,"categories":[{"id":12,"slug":"javascript-frameworks","name":"JavaScript frameworks"}' \
        ',{"id":18,"slug":"web-frameworks","name":"Web frameworks"},{"id":22,"slug":"web-servers",' \
        '"name":"Web servers"},{"id":57,"slug":"static-site-generator","name":"Static site generator"}]}' \
        ',{"slug":"google-font-api","name":"Google Font API","confidence":100,"version":null,"icon":' \
        '"Google Font API.png","website":"http://google.com/fonts","cpe":null,"categories":[{"id":17,' \
        '"slug":"font-scripts","name":"Font scripts"}]},{"slug":"google-analytics","name":"Google ' \
        'Analytics","confidence":100,"version":null,"icon":"Google Analytics.svg","website":"http://' \
        'google.com/analytics","cpe":null,"categories":[{"id":10,"slug":"analytics","name":"Analytics"}]}' \
        ',{"slug":"core-js","name":"core-js","confidence":100,"version":"2.6.12","icon":"core-js.png",' \
        '"website":"https://github.com/zloirock/core-js","cpe":null,"categories":[{"id":59,"slug":' \
        '"javascript-libraries","name":"JavaScript libraries"}]},{"slug":"jsdelivr","name":"jsDelivr",' \
        '"confidence":100,"version":null,"icon":"jsdelivr-icon.svg","website":"https://www.jsdelivr.com/"' \
        ',"cpe":null,"categories":[{"id":31,"slug":"cdn","name":"CDN"}]},{"slug":"recaptcha","name":' \
        '"reCAPTCHA","confidence":100,"version":null,"icon":"reCAPTCHA.svg","website":"https://' \
        'www.google.com/recaptcha/","cpe":null,"categories":[{"id":16,"slug":"security","name":' \
        '"Security"}]},{"slug":"netlify","name":"Netlify","confidence":100,"version":null,"icon":' \
        '"Netlify.svg","website":"https://www.netlify.com/","cpe":null,"categories":[{"id":62,"slug":' \
        '"paas","name":"PaaS"},{"id":31,"slug":"cdn","name":"CDN"}]},{"slug":"webpack","name":"webpack",' \
        '"confidence":100,"version":null,"icon":"webpack.svg","website":"https://webpack.js.org/",' \
        '"cpe":null,"categories":[{"id":19,"slug":"miscellaneous","name":"Miscellaneous"}]},{"slug":' \
        '"prism","name":"Prism","confidence":100,"version":null,"icon":"Prism.svg","website":' \
        '"http://prismjs.com","cpe":null,"categories":[{"id":19,"slug":"miscellaneous","name":' \
        '"Miscellaneous"}]}]}'


def testAgentWappalyzer_whenDomainNameAsset_returnFingerprintsAndVulnerabilities(domain_message, wappalyzer_test_agent,
                                                                                 agent_mock, agent_persist_mock, fp):
    """Tests running the agent and emitting vulnerabilities for a domain asset."""
    del agent_persist_mock
    fp.register('node src/drivers/npm/cli.js https://test.ostorlab.co:443',
                stdout=OUPUT)
    wappalyzer_test_agent.start()
    wappalyzer_test_agent.process(domain_message)
    assert len(agent_mock) > 0
    assert 'v3.report.vulnerability' in [a.selector for a in agent_mock]
    assert 'v3.fingerprint.domain_name.service.library' in [a.selector for a in agent_mock]


def testAgentWappalyzer_whenDomainAlreadyScans_doNothing(domain_message, wappalyzer_test_agent, agent_mock,
                                                         agent_persist_mock, fp):
    """Ensure wappalyzer agent does not process the same message multiple times."""
    del agent_persist_mock
    fp.register('node src/drivers/npm/cli.js https://test.ostorlab.co:443',
                stdout=OUPUT)
    wappalyzer_test_agent.start()
    wappalyzer_test_agent.process(domain_message)
    count_first = len(agent_mock)
    wappalyzer_test_agent.process(domain_message)
    count_second = len(agent_mock)
    assert count_second - count_first == 0


def testAgentWappalyzer_whenHTTPSLinkAsset_returnFingerprintsAndVulnerabilities(https_link_message,
                                                                                wappalyzer_test_agent, agent_mock,
                                                                                agent_persist_mock, fp):
    """Ensure wappalyzer agent emits the correct vulnerabilities, and library out message for a link input message.
    Also ensures the correct compute of the port and schema from the target link: Case of https schema.
    """
    del agent_persist_mock
    fp.register('node src/drivers/npm/cli.js https://ostorlab.co',
                stdout=OUPUT)
    wappalyzer_test_agent.start()
    wappalyzer_test_agent.process(https_link_message)
    assert len(agent_mock) > 0
    assert 'v3.report.vulnerability' in [a.selector for a in agent_mock]
    assert 'v3.fingerprint.domain_name.service.library' in [a.selector for a in agent_mock]
    assert any(out_msg.data.get('port') == 443 and out_msg.data.get('schema') == 'https' for out_msg in agent_mock)


def testAgentWappalyzer_whenHTTPLinkAsset_returnFingerprintsAndVulnerabilities(http_link_message,
                                                                               wappalyzer_test_agent, agent_mock,
                                                                               agent_persist_mock, fp):
    """Ensure wappalyzer agent emits the correct vulnerabilities, and library out message for a link input message.
    Also ensures the correct compute of the port and schema from the target link: Case of http schema.
    """
    del agent_persist_mock
    fp.register('node src/drivers/npm/cli.js http://ostorlab.co',
                stdout=OUPUT)
    wappalyzer_test_agent.start()
    wappalyzer_test_agent.process(http_link_message)
    assert len(agent_mock) > 0
    assert 'v3.report.vulnerability' in [a.selector for a in agent_mock]
    assert 'v3.fingerprint.domain_name.service.library' in [a.selector for a in agent_mock]
    assert any(out_msg.data.get('port') == 80 and out_msg.data.get('schema') == 'http' for out_msg in agent_mock)
