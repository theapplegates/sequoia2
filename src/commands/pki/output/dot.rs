use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::Write;
use std::time::SystemTime;

use dot_writer::Attributes;
use dot_writer::DotWriter;
use dot_writer::Scope;
use dot_writer::Shape;

use openpgp::packet::UserID;
use openpgp::Fingerprint;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use sequoia_wot as wot;
use wot::Depth;
use wot::Path;
use wot::Roots;
use wot::FULLY_TRUSTED;

use crate::commands::pki::output::OutputType;

const DOT_INSTRUCTIONS: &'static str = "\
//
// Example: To convert DOT to SVG (on many systems):
//
// sq --output-format dot pki ... | dot -Tsvg -o output.svg
//
// For further information on using graphviz see:
// https://graphviz.org/doc/info/command.html
";
const DOT_ROOT_FILL_COLOR: &'static str = "mediumpurple2";
const DOT_TARGET_OK_FILL_COLOR: &'static str = "lightgreen";
const DOT_TARGET_FAIL_FILL_COLOR: &'static str = "indianred2";
const DOT_NODE_FILL_COLOR: &'static str = "grey";

/// Return UserID as String and remove (backslash escaped) double quotes
///
/// In quoted strings in DOT, the only escaped character is double-quote (").
/// That is, in quoted strings, the dyad \" is converted to "; all other
/// characters are left unchanged. In particular, \\ remains \\. Layout engines
/// may apply additional escape sequences.
fn escape_userid(userid: &UserID) -> String {
    format!("{}", userid)
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
}

/// Add a legend graph to an existing Scope
///
/// The legend graph provides information on color coding of the various nodes,
/// as well as the targeted trust amount, whether looking at gossip and whether
/// the data is used as a certification network.
fn add_legend_graph(
    container: &mut Scope,
    required_amount: usize,
    gossip: bool,
    certification_network: bool,
) {
    let mut legend = container.cluster();
    legend.set_label("Graph legend");
    legend
        .node_attributes()
        .set("shape", "note", false)
        .set_fill_color(dot_writer::Color::White);
    let mut legend_edges = Vec::new();

    legend_edges.push(format!("\"Trust root\""));
    legend
        .node_named(legend_edges.last().expect("Just added a legend node."))
        .set("fillcolor", DOT_ROOT_FILL_COLOR, false);

    legend_edges.push(format!("\"Intermediate introducer\""));
    legend
        .node_named(legend_edges.last().expect("Just added a legend node."))
        .set("fillcolor", DOT_NODE_FILL_COLOR, false);

    legend_edges.push(format!("\"Authenticated target\""));
    legend
        .node_named(legend_edges.last().expect("Just added a legend node."))
        .set("fillcolor", DOT_TARGET_OK_FILL_COLOR, false);

    legend_edges.push(format!("\"Unauthenticated target\""));
    legend
        .node_named(legend_edges.last().expect("Just added a legend node."))
        .set("fillcolor", DOT_TARGET_FAIL_FILL_COLOR, false);

    legend_edges.push(format!(
        "\"target trust amount: {}%\"",
        (100 * required_amount) / FULLY_TRUSTED,
    ));
    legend.node_named(legend_edges.last().expect("Just added a legend node."));

    if gossip {
        legend_edges.push(String::from("gossip"));
        legend.node_named(
            legend_edges.last().expect("Just added a legend node."),
        );
    }

    if certification_network {
        legend_edges.push(String::from("certification network"));
        legend.node_named(
            legend_edges.last().expect("Just added a legend node."),
        );
    }

    // internal edges are used for arranging nodes in the cluster
    // and are therefore invisible
    let mut edge_attributes = legend.edge_attributes();
    edge_attributes
        .set_font_size(0.1)
        .set_style(dot_writer::Style::Invisible)
        .set_arrow_size(0.1)
        .set_arrow_tail(dot_writer::ArrowType::InvEmpty);
    drop(edge_attributes);

    // add edges for all legend nodes so that they can be arranged within the
    // cluster
    for edge in legend_edges.windows(2) {
        legend.edge(&edge[0], &edge[1]);
    }
}

/// The output representation of a certification
///
/// An OutputCertification tracks the issuer's and target's Fingerprint, as well
/// as the target's UserID.
/// Furthermore, the trust amount and depth of the certification and its
/// (optional) creation and expiry timestamps are covered.
#[derive(Clone, Debug)]
pub struct OutputCertification {
    issuer_fingerprint: Fingerprint,
    target_fingerprint: Fingerprint,
    target_uid: UserID,
    creation: SystemTime,
    expiry: Option<SystemTime>,
    trust_amount: usize,
    depth: Depth,
}

impl OutputCertification {
    pub fn new(
        issuer_fingerprint: Fingerprint,
        target_fingerprint: Fingerprint,
        target_uid: UserID,
        creation: SystemTime,
        expiry: Option<SystemTime>,
        trust_amount: usize,
        depth: Depth,
    ) -> Self {
        Self {
            issuer_fingerprint,
            target_fingerprint,
            target_uid,
            creation,
            expiry,
            trust_amount,
            depth,
        }
    }
}

/// The output representation of a Path
///
/// A number uniquely identifies an OutputPath amongst others.
#[derive(Debug)]
pub struct OutputPath {
    // The unique number of the OutputPath (an OutputNetwork provides between
    // 0 and n OutputPaths per target Fingerprint)
    number: usize,
    certifications: Vec<OutputCertification>,
}

impl OutputPath {
    pub fn new(number: usize) -> Self {
        Self {
            number,
            certifications: Vec::new(),
        }
    }

    /// Return the certifications of the OutputPath in an iterator
    pub fn certifications(&self) -> impl Iterator<Item = &OutputCertification> {
        self.certifications.iter()
    }

    /// Add an OutputCertification to the list of certifications
    pub fn add_certification(
        &mut self,
        issuer_fingerprint: Fingerprint,
        target_fingerprint: Fingerprint,
        target_uid: UserID,
        creation: SystemTime,
        expiry: Option<SystemTime>,
        trust_amount: usize,
        depth: Depth,
    ) {
        self.certifications.push(OutputCertification::new(
            issuer_fingerprint,
            target_fingerprint,
            target_uid,
            creation,
            expiry,
            trust_amount,
            depth,
        ))
    }
}

/// The output representation of a cert
///
/// It tracks the Fingerprint and UserIDs (as well as their trust amount and
/// indicator whether they are a target of a Path) and an indicator whether the
/// Fingerprint serves as trust root.
#[derive(Clone, Debug)]
pub struct OutputCert {
    keyhandle: Fingerprint,
    /// HashMap tracking UserID and accompanying trust amount and whether the
    /// UserID is the target of a Path
    userids: HashMap<UserID, (usize, bool)>,
    // does the cert serve as trust root?
    is_root: bool,
}

impl OutputCert {
    pub fn new(
        keyhandle: &Fingerprint,
        userid: UserID,
        trust_amount: usize,
        is_root: bool,
        is_target: bool,
    ) -> Self {
        Self {
            keyhandle: keyhandle.clone(),
            userids: HashMap::from([(userid, (trust_amount, is_target))]),
            is_root,
        }
    }

    /// Get the data for a provided UserID
    pub fn get_userid_data(&self, userid: &UserID) -> Option<&(usize, bool)> {
        self.userids.get(userid)
    }

    /// Add a UserID and its associated data to the list of userids
    pub fn add_userid_data(&mut self, userid: UserID, data: (usize, bool)) {
        self.userids.insert(userid, data);
    }

    /// Update the trust amount of a UserID
    ///
    /// If no matching UserID is found, it is first created
    /// (the bool indicating whether the UserID is the target of a Path is set
    /// to false)
    pub fn update_trust_amount(
        &mut self,
        userid: &UserID,
        trust_amount: usize,
    ) {
        match self.userids.get_mut(userid) {
            Some(userid_data) => {
                userid_data.0 = trust_amount;
            }
            None => {
                self.add_userid_data(userid.to_owned(), (trust_amount, false));
            }
        }
    }

    /// Update whether the OutputCert serves as trust root
    ///
    /// Once this value is set to true it is not set to false anymore
    pub fn set_is_root(&mut self, is_root: bool) {
        self.is_root = self.is_root || is_root
    }

    /// Update whether a UserID is the target of a Path
    ///
    /// Once this value is set to true it is not set to false anymore
    pub fn set_is_target(&mut self, userid: &UserID, is_target: bool) {
        if let Some(userid_data) = self.userids.get_mut(userid) {
            userid_data.1 = userid_data.1 || is_target;
        }
    }
}

/// The output representation of a Network
///
/// An OutputNetwork tracks the required trust amount for the network, a list
/// of OutputCerts in the network, and a hash map containing key-value pairs
/// consisting of  Path target Fingerprints and lists of OutputPaths.
#[derive(Debug)]
pub struct OutputNetwork {
    required_amount: usize,
    gossip: bool,
    certification_network: bool,
    certs: Vec<OutputCert>,
    paths: HashMap<Fingerprint, Vec<OutputPath>>,
}

impl OutputNetwork {
    pub fn new(
        required_amount: usize,
        gossip: bool,
        certification_network: bool,
    ) -> Self {
        let certs = Vec::new();
        let paths = HashMap::new();
        OutputNetwork {
            required_amount,
            gossip,
            certification_network,
            certs,
            paths,
        }
    }

    /// Try to add an OutputCert and return it
    ///
    /// If no OutputCert identified by keyhandle exists, one is created.
    pub fn try_add_cert(
        &mut self,
        keyhandle: Fingerprint,
        userid: UserID,
        trust_amount: usize,
        is_root: bool,
        is_target: bool,
    ) -> &OutputCert {
        // take `self.certs` out of `self` to help the borrow checker
        let mut certs = std::mem::replace(&mut self.certs, vec![]);
        if let Some(cert) = Self::get_mut_cert(&mut certs, &keyhandle) {
            if cert.get_userid_data(&userid).is_none() {
                cert.add_userid_data(
                    userid.to_owned(),
                    (trust_amount, is_target),
                );
            }
        } else {
            certs.push(OutputCert::new(
                &keyhandle,
                userid,
                trust_amount,
                is_root,
                is_target,
            ));
        }
        self.certs = certs;

        self.get_cert(&keyhandle).expect("A cert was just added")
    }

    /// Return an OutputCert matching a Fingerprint
    pub fn get_cert(&self, keyhandle: &Fingerprint) -> Option<&OutputCert> {
        self.certs.iter().find(|x| &x.keyhandle == keyhandle)
    }

    /// Get a mutable reference to an OutputCert matching a Fingerprint
    pub fn get_mut_cert<'a>(
        certs: &'a mut Vec<OutputCert>,
        keyhandle: &Fingerprint,
    ) -> Option<&'a mut OutputCert> {
        if let Some(i) = certs.iter().position(|x| &x.keyhandle == keyhandle) {
            Some(&mut certs[i])
        } else {
            None
        }
    }

    /// Get a mutable reference to an OutputPath matching a Fingerprint (of an
    /// OutputCert) and a number (of a specific OutputPath)
    pub fn get_mut_path(
        &mut self,
        fingerprint: &Fingerprint,
        number: usize,
    ) -> Option<&mut OutputPath> {
        if let Some(path_list) = self.paths.get_mut(fingerprint) {
            path_list.iter_mut().filter(|x| x.number == number).last()
        } else {
            None
        }
    }

    /// Add an empty OutputPath to the list of paths using a Fingerprint and a
    /// number
    pub fn add_path(&mut self, fingerprint: &Fingerprint, number: usize) {
        if let Some(path_list) = self.paths.get_mut(fingerprint) {
            path_list.push(OutputPath::new(number));
        } else {
            let mut path_list = Vec::new();
            path_list.push(OutputPath::new(number));
            self.paths.insert(fingerprint.clone(), path_list);
        }
    }

    /// Add an OutputCertification to a list of OutputPaths matching a
    /// Fingerprint and a path number
    pub fn add_certification(
        &mut self,
        path_target_fingerprint: &Fingerprint,
        path_number: usize,
        target_fingerprint: Fingerprint,
        target_uid: UserID,
        issuer_fingerprint: Fingerprint,
        creation: SystemTime,
        expiry: Option<SystemTime>,
        trust_amount: usize,
        depth: Depth,
    ) {
        self.add_path(&path_target_fingerprint, path_number);
        if let Some(path) =
            self.get_mut_path(&path_target_fingerprint, path_number)
        {
            path.add_certification(
                issuer_fingerprint,
                target_fingerprint,
                target_uid,
                creation,
                expiry,
                trust_amount,
                depth,
            );
        } else {
            panic!(
                "There is no path associated with keyhandle {} and number {}!",
                target_fingerprint, path_number
            );
        }
    }

    /// Return the OutputCerts in an Iterator
    pub fn certs(&self) -> impl Iterator<Item = &OutputCert> {
        self.certs.iter()
    }

    /// Return an Iterator of tuples of Fingerprint and OutputPaths
    pub fn paths(
        &self,
    ) -> impl Iterator<Item = (&Fingerprint, &Vec<OutputPath>)> {
        self.paths.iter()
    }

    /// Create the edge label for a certification
    fn create_certification_edge_label(
        trust_amount: usize,
        creation: Option<SystemTime>,
        expiry: Option<SystemTime>,
        depth: Option<Depth>,
    ) -> String {
        let mut certification_label = String::new();

        if trust_amount < FULLY_TRUSTED {
            certification_label.push_str(&format!(
                "partially certified (amount: {} of 120)",
                trust_amount,
            ));
        } else {
            certification_label.push_str("certified");
        }

        if let Some(time) = creation {
            certification_label.push_str(&format!(
                " on {}",
                chrono::DateTime::<chrono::Utc>::from(time).format("%Y-%m-%d")
            ));
        }

        if let Some(time) = expiry {
            certification_label.push_str(&format!(
                " (expiry: {})",
                chrono::DateTime::<chrono::Utc>::from(time).format("%Y-%m-%d")
            ));
        }

        if creation.is_some() || expiry.is_some() {
            certification_label.push_str("\n");
        }

        match depth {
            Some(Depth::Limit(depth)) => {
                if depth > 0 {
                    certification_label.push_str(" as a");
                    if trust_amount != FULLY_TRUSTED {
                        certification_label.push_str(&format!(
                            " partially trusted ({} of 120)",
                            trust_amount,
                        ));
                    } else {
                        certification_label.push_str(" fully trusted");
                    }
                    if depth == 1 {
                        certification_label.push_str(&format!(
                            " introducer (depth: {})",
                            depth,
                        ));
                    } else {
                        certification_label.push_str(&format!(
                            " meta-introducer (depth: {})",
                            depth,
                        ));
                    }
                }
            }
            Some(Depth::Unconstrained) => {
                certification_label.push_str(" as a");
                if trust_amount != FULLY_TRUSTED {
                    certification_label.push_str(&format!(
                        " partially trusted ({} of 120)",
                        trust_amount,
                    ));
                } else {
                    certification_label.push_str(" fully trusted");
                }
                certification_label.push_str(" issuer (depth: infinite)");
            }
            _ => {}
        }
        certification_label
    }

    /// Write the OutputNetwork to an output (in DOT format)
    pub fn dot(&self, writer: &mut dyn Write) -> Result<()> {
        let mut output_bytes = Vec::new();
        let mut dot_writer = DotWriter::from(&mut output_bytes);
        dot_writer.set_pretty_print(true);

        // the base graph with all relevant node settings
        let mut base_graph = dot_writer.digraph();
        base_graph
            .node_attributes()
            .set_shape(Shape::Rectangle)
            .set_style(dot_writer::Style::Filled);

        // container cluster for all further clusters and nodes
        let mut container = base_graph.cluster();

        for target_cert in self.certs() {
            let mut cert_cluster = container.cluster();
            cert_cluster.set("color", DOT_NODE_FILL_COLOR, false);

            // internal edges are used for arranging nodes in the cluster
            // and are therefore invisible
            let mut edge_attributes = cert_cluster.edge_attributes();
            edge_attributes.set_style(dot_writer::Style::Invisible);
            drop(edge_attributes);

            // sort the UserIDs and accompanying data by reverse amount and
            // UserID
            let mut userid_data =
                target_cert.userids.iter().collect::<Vec<_>>();
            userid_data.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));

            // add all edges between Fingerprints and the foreign (to their own
            // key) UserIDs they are certifying
            let mut cert_edges = Vec::new();
            for (userid, (trust_amount, is_target)) in userid_data {
                let node_name = format!(
                    "\"{}_{}\"",
                    &target_cert.keyhandle,
                    escape_userid(&userid)
                );

                cert_edges.push(node_name.clone());

                let mut node = cert_cluster.node_named(&node_name);
                // if it is a trust root or not a target of a path, we do not
                // need to add trust amount
                if target_cert.is_root || !is_target {
                    node.set_label(&format!("{}", escape_userid(&userid)));
                } else {
                    node.set_label(&format!(
                        "{}\n({}%)",
                        escape_userid(&userid),
                        (trust_amount * 100) / FULLY_TRUSTED,
                    ));
                }
                node.set(
                    "fillcolor",
                    if *is_target {
                        if trust_amount >= &self.required_amount {
                            DOT_TARGET_OK_FILL_COLOR
                        } else {
                            DOT_TARGET_FAIL_FILL_COLOR
                        }
                    } else {
                        DOT_NODE_FILL_COLOR
                    },
                    false,
                );
            }

            // add node for Fingerprint
            let node_name = format!("\"{}\"", &target_cert.keyhandle);
            cert_edges.push(node_name.clone());
            let mut keyhandle_node = cert_cluster.node_named(&node_name);
            keyhandle_node.set_label(&format!("{}", target_cert.keyhandle));
            if target_cert.is_root {
                keyhandle_node.set("fillcolor", DOT_ROOT_FILL_COLOR, false);
            }
            drop(keyhandle_node);

            // add edges for all UserID and the Fingerprint nodes so that they
            // can be arranged within the cluster
            for edge in cert_edges.windows(2) {
                cert_cluster.edge(&edge[0], &edge[1]);
            }
        }

        // add edges for all certifications of Fingerprints on UserIDs
        let mut known_certifications = BTreeSet::new();
        for (_keyhandle, paths) in self.paths() {
            for path in paths.iter() {
                for certification in path.certifications() {
                    let entry = format!(
                        "{}_{}_{}",
                        &certification.issuer_fingerprint,
                        &certification.target_fingerprint,
                        &certification.target_uid,
                    );

                    if !known_certifications.contains(&entry) {
                        // as gossip output is likely already very convoluted,
                        // do not include self-signatures
                        if !(self.gossip
                            && &certification.issuer_fingerprint
                                == &certification.target_fingerprint)
                            || !self.gossip
                        {
                            let edge = container.edge(
                                format!(
                                    "\"{}\"",
                                    &certification.issuer_fingerprint
                                ),
                                format!(
                                    "\"{}_{}\"",
                                    &certification.target_fingerprint,
                                    escape_userid(&certification.target_uid),
                                ),
                            );
                            let certification_label =
                                OutputNetwork::create_certification_edge_label(
                                    certification.trust_amount,
                                    Some(certification.creation),
                                    certification.expiry,
                                    Some(certification.depth),
                                );
                            // use xlabel when generating gossip output,
                            // so it is less likely to run into init_rank
                            // issues: https://gitlab.com/graphviz/graphviz/-/issues/1213
                            if self.gossip {
                                edge.attributes()
                                    .set("xlabel", &certification_label, true)
                                    .set("decorate", "true", false);
                            } else {
                                edge.attributes()
                                    .set_label(&certification_label)
                                    .set("decorate", "true", false);
                            }

                            known_certifications.insert(entry);
                        }
                    }
                }
            }
        }

        // add a legend graph
        add_legend_graph(
            &mut container,
            self.required_amount,
            self.gossip,
            self.certification_network,
        );

        drop(container);
        drop(base_graph);
        if let Ok(data) = String::from_utf8(output_bytes) {
            writeln!(
                writer,
                "// Created by {} {}",
                env!("CARGO_BIN_NAME"),
                env!("CARGO_PKG_VERSION")
            )?;
            writeln!(writer, "{}", DOT_INSTRUCTIONS)?;
            writeln!(writer, "{}", data)?;
        }

        Ok(())
    }
}

/// The DOT specific implementation of an OutputNetwork representation
///
/// DotOutputNetwork tracks an OutputNetwork and the roots for it.
pub struct DotOutputNetwork<'a> {
    output_network: OutputNetwork,
    roots: &'a Roots,
}

impl<'a> DotOutputNetwork<'a> {
    /// Create a new DotOutputNetwork
    pub fn new(
        required_amount: usize,
        roots: &'a Roots,
        gossip: bool,
        certification_network: bool,
    ) -> Self {
        let output_network =
            OutputNetwork::new(required_amount, gossip, certification_network);
        Self {
            output_network,
            roots,
        }
    }
}

impl<'a> OutputType for DotOutputNetwork<'a> {
    /// Add paths to the OutputNetwork
    fn add_paths(
        &mut self,
        paths: Vec<(Path, usize)>,
        fingerprint: &Fingerprint,
        userid: &UserID,
        aggregated_amount: usize,
    ) -> Result<()> {
        match OutputNetwork::get_mut_cert(
            &mut self.output_network.certs,
            &fingerprint.to_owned(),
        ) {
            Some(cert) => {
                cert.update_trust_amount(userid, aggregated_amount);
                cert.set_is_root(self.roots.is_root(fingerprint));
                cert.set_is_target(userid, true);
            }
            None => {
                self.output_network.try_add_cert(
                    fingerprint.to_owned(),
                    userid.to_owned(),
                    aggregated_amount,
                    self.roots.is_root(fingerprint),
                    true,
                );
            }
        }

        for (path_number, (path, _path_trust_amount)) in
            paths.iter().enumerate()
        {
            let issuer_fingerprint = path.root().fingerprint();

            if self.output_network.get_cert(&issuer_fingerprint).is_none() {
                let certifier_userid = if path.certifications().count() == 0 {
                    userid
                } else if let Some(userid) = path.root().primary_userid() {
                    userid.userid()
                } else {
                    userid
                };
                self.output_network.try_add_cert(
                    issuer_fingerprint,
                    certifier_userid.to_owned(),
                    0,
                    self.roots.is_root(&path.root().fingerprint()),
                    false,
                );
            }

            // sort the certifications by reverse amount and issuer
            let mut certifications = path.certifications().collect::<Vec<_>>();
            certifications.sort_by(|a, b| {
                b.amount().cmp(&a.amount()).then(
                    a.issuer().fingerprint().cmp(&b.issuer().fingerprint()),
                )
            });

            for certification in certifications {
                let certification_target_userid =
                    if let Some(target_userid) = certification.userid() {
                        target_userid
                    } else {
                        userid
                    };

                let target_cert_is_root =
                    self.roots.is_root(certification.target().fingerprint());

                self.output_network.try_add_cert(
                    certification.target().fingerprint(),
                    certification_target_userid.to_owned(),
                    0,
                    target_cert_is_root,
                    false,
                );

                self.output_network.add_certification(
                    &path.target().fingerprint(),
                    path_number,
                    certification.target().fingerprint(),
                    certification_target_userid.to_owned(),
                    certification.issuer().fingerprint(),
                    certification.creation_time(),
                    certification.expiration_time(),
                    certification.amount(),
                    certification.depth(),
                )
            }
        }
        Ok(())
    }

    /// Write the DotOutputNetwork to output
    fn finalize(&mut self) -> Result<()> {
        self.output_network.dot(&mut std::io::stdout())?;
        Ok(())
    }
}
